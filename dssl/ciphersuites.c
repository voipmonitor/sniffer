/*
** This file is a part of DSSL library.
**
** Copyright (C) 2005-2009, Atomic Labs, Inc.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/
#include "stdinc.h"
#include "ciphersuites.h"

static DSSL_CipherSuite ssl3suites[] = 
{
	/* RFC 2246, RFC 4346, RFC 5246 */
	{ 0x0000, 0, "null", 0, "null", "null", NULL }, /* TLS_NULL_WITH_NULL_NULL */
	{ 0x0001, 0, LN_rsa, 0, "null", LN_md5, NULL }, /* TLS_RSA_WITH_NULL_MD5 */
	{ 0x0002, 0, LN_rsa, 0, "null", LN_sha1, NULL }, /* TLS_RSA_WITH_NULL_SHA */
	{ 0x0003, 0, "rsa-export", 40, LN_rc4, LN_md5, NULL }, /* TLS_RSA_EXPORT_WITH_RC4_40_MD5 */
	{ 0x0004, 0, LN_rsa, 0, LN_rc4, LN_md5, NULL }, /* TLS_RSA_WITH_RC4_128_MD5 */
	{ 0x0005, 0, LN_rsa, 0, LN_rc4, LN_sha1, NULL }, /* TLS_RSA_WITH_RC4_128_SHA */
	{ 0x0006, 0, "rsa-export", 40, LN_rc2_cbc, LN_md5, NULL }, /* TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 */
	{ 0x0007, 0, LN_rsa, 0, LN_idea_cbc, LN_sha1, NULL }, /* TLS_RSA_WITH_IDEA_CBC_SHA */
	{ 0x0008, 0, "rsa-export", 40, LN_des_cbc, LN_sha1, NULL }, /* TLS_RSA_EXPORT_WITH_DES40_CBC_SHA */
	{ 0x0009, 0, LN_rsa, 0, LN_des_cbc, LN_sha1, NULL }, /* TLS_RSA_WITH_DES_CBC_SHA */
	{ 0x000a, 0, LN_rsa, 0, LN_des_ede3_cbc, LN_sha1, NULL }, /* TLS_RSA_WITH_3DES_EDE_CBC_SHA */
	{ 0x000b, 0, "dh-dss-export", 40, LN_des_cbc, LN_sha1, NULL }, /* TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA */
	{ 0x000c, 0, "dh-dss", 0, LN_des_cbc, LN_sha1, NULL }, /* TLS_DH_DSS_WITH_DES_CBC_SHA */
	{ 0x000d, 0, "dh-dss", 0, LN_des_ede3_cbc, LN_sha1, NULL }, /* TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA */
	{ 0x000e, 0, "dh-rsa-export", 40, LN_des_cbc, LN_sha1, NULL }, /* TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA */
	{ 0x000f, 0, "dh-rsa", 0, LN_des_cbc, LN_sha1, NULL }, /* TLS_DH_RSA_WITH_DES_CBC_SHA */
	{ 0x0010, 0, "dh-rsa", 0, LN_des_ede3_cbc, LN_sha1, NULL }, /* TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA */
	{ 0x0011, 0, "dhe-dss-export", 40, LN_des_cbc, LN_sha1, NULL }, /* TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA */
	{ 0x0012, 0, "dhe-dss", 0, LN_des_cbc, LN_sha1, NULL }, /* TLS_DHE_DSS_WITH_DES_CBC_SHA */
	{ 0x0013, 0, "dhe-dss", 0, LN_des_ede3_cbc, LN_sha1, NULL }, /* TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA */
	{ 0x0014, 0, "dhe-rsa-export", 40, LN_des_cbc, LN_sha1, NULL }, /* TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA */
	{ 0x0015, 0, "dhe-rsa", 0, LN_des_cbc, LN_sha1, NULL }, /* TLS_DHE_RSA_WITH_DES_CBC_SHA */
	{ 0x0016, 0, "dhe-rsa", 0, LN_des_ede3_cbc, LN_sha1, NULL }, /* TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA */
	{ 0x0017, 0, "dh-anon-export", 40, LN_rc4, LN_md5, NULL }, /* TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 */
	{ 0x0018, 0, "dh-anon", 0, LN_rc4, LN_md5, NULL }, /* TLS_DH_anon_WITH_RC4_128_MD5 */
	{ 0x0019, 0, "dh-anon-export", 40, LN_des_cbc, LN_sha1, NULL }, /* TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA */
	{ 0x001a, 0, "dh-anon", 0, LN_des_cbc, LN_sha1, NULL }, /* TLS_DH_anon_WITH_DES_CBC_SHA */
	{ 0x001b, 0, "dh-anon", 0, LN_des_ede3_cbc, LN_sha1, NULL }, /* TLS_DH_anon_WITH_3DES_EDE_CBC_SHA */
	{ 0x001c, 0, "fortezza-kea", 0, "null", LN_sha1, NULL }, /* SSL_FORTEZZA_KEA_WITH_NULL_SHA */
	{ 0x001d, 0, "fortezza-kea", 0, "fortezza-cbc", LN_sha1, NULL }, /* SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA */
	/* RFC 2712 */
	{ 0x001E, 0, "krb5", 0, LN_des_cbc, LN_sha1, NULL }, /* TLS_KRB5_WITH_DES_CBC_SHA */
	{ 0x001F, 0, "krb5", 0, LN_des_ede3_cbc, LN_sha1, NULL }, /* TLS_KRB5_WITH_3DES_EDE_CBC_SHA */
	{ 0x0020, 0, "krb5", 0, LN_rc4, LN_sha1, NULL }, /* TLS_KRB5_WITH_RC4_128_SHA */
	{ 0x0021, 0, "krb5", 0, LN_idea_cbc, LN_sha1, NULL }, /* TLS_KRB5_WITH_IDEA_CBC_SHA */
	{ 0x0022, 0, "krb5", 0, LN_des_cbc, LN_md5, NULL }, /* TLS_KRB5_WITH_DES_CBC_MD5 */
	{ 0x0023, 0, "krb5", 0, LN_des_ede3_cbc, LN_md5, NULL }, /* TLS_KRB5_WITH_3DES_EDE_CBC_MD5 */
	{ 0x0024, 0, "krb5", 0, LN_rc4, LN_md5, NULL }, /* TLS_KRB5_WITH_RC4_128_MD5 */
	{ 0x0025, 0, "krb5", 0, LN_idea_cbc, LN_md5, NULL }, /* TLS_KRB5_WITH_IDEA_CBC_MD5 */
	{ 0x0026, 0, "krb5-export", 40, LN_des_cbc, LN_sha1, NULL }, /* TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA */
	{ 0x0027, 0, "krb5-export", 40, LN_rc2_cbc, LN_sha1, NULL }, /* TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA */
	{ 0x0028, 0, "krb5-export", 40, LN_rc4, LN_sha1, NULL }, /* TLS_KRB5_EXPORT_WITH_RC4_40_SHA */
	{ 0x0029, 0, "krb5-export", 40, LN_des_cbc, LN_md5, NULL }, /* TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 */
	{ 0x002A, 0, "krb5-export", 40, LN_rc2_cbc, LN_md5, NULL }, /* TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 */
	{ 0x002B, 0, "krb5-export", 40, LN_rc4, LN_md5, NULL }, /* TLS_KRB5_EXPORT_WITH_RC4_40_MD5 */
	/* RFC 4785 */
	{ 0x002C, 0, "psk", 0, "null", LN_sha1, NULL }, /* TLS_PSK_WITH_NULL_SHA */
	{ 0x002D, 0, "dhe-psk", 0, "null", LN_sha1, NULL }, /* TLS_DHE_PSK_WITH_NULL_SHA */
	{ 0x002E, 0, "rsa-psk", 0, "null", LN_sha1, NULL }, /* TLS_RSA_PSK_WITH_NULL_SHA */
	/* RFC 5246 */
	{ 0x002F, 0, LN_rsa, 0, LN_aes_128_cbc, LN_sha1, NULL }, /* TLS_RSA_WITH_AES_128_CBC_SHA */
	{ 0x0030, 0, "dh-dss", 0, LN_aes_128_cbc, LN_sha1, NULL }, /* TLS_DH_DSS_WITH_AES_128_CBC_SHA */
	{ 0x0031, 0, "dh-rsa", 0, LN_aes_128_cbc, LN_sha1, NULL }, /* TLS_DH_RSA_WITH_AES_128_CBC_SHA */
	{ 0x0032, 0, "dhe-dss", 0, LN_aes_128_cbc, LN_sha1, NULL }, /* TLS_DHE_DSS_WITH_AES_128_CBC_SHA */
	{ 0x0033, 0, "dhe-rsa", 0, LN_aes_128_cbc, LN_sha1, NULL }, /* TLS_DHE_RSA_WITH_AES_128_CBC_SHA */
	{ 0x0034, 0, "dh-anon", 0, LN_aes_128_cbc, LN_sha1, NULL }, /* TLS_DH_anon_WITH_AES_128_CBC_SHA */
	{ 0x0035, 0, LN_rsa, 0, LN_aes_256_cbc, LN_sha1, NULL }, /* TLS_RSA_WITH_AES_256_CBC_SHA */
	{ 0x0036, 0, "dh-dss", 0, LN_aes_256_cbc, LN_sha1, NULL }, /* TLS_DH_DSS_WITH_AES_256_CBC_SHA */
	{ 0x0037, 0, "dh-rsa", 0, LN_aes_256_cbc, LN_sha1, NULL }, /* TLS_DH_RSA_WITH_AES_256_CBC_SHA */
	{ 0x0038, 0, "dhe-dss", 0, LN_aes_256_cbc, LN_sha1, NULL }, /* TLS_DHE_DSS_WITH_AES_256_CBC_SHA */
	{ 0x0039, 0, "dhe-rsa", 0, LN_aes_256_cbc, LN_sha1, NULL }, /* TLS_DHE_RSA_WITH_AES_256_CBC_SHA */
	{ 0x003A, 0, "dh-anon", 0, LN_aes_256_cbc, LN_sha1, NULL }, /* TLS_DH_anon_WITH_AES_256_CBC_SHA */
	{ 0x003B, 0, LN_rsa, 0, "null", LN_sha256, NULL }, /* TLS_RSA_WITH_NULL_SHA256 */
	{ 0x003C, 0, LN_rsa, 0, LN_aes_128_cbc, LN_sha256, NULL }, /* TLS_RSA_WITH_AES_128_CBC_SHA256 */
	{ 0x003D, 0, LN_rsa, 0, LN_aes_256_cbc, LN_sha256, NULL }, /* TLS_RSA_WITH_AES_256_CBC_SHA256 */
	{ 0x003E, 0, "dh-dss", 0, LN_aes_128_cbc, LN_sha256, NULL }, /* TLS_DH_DSS_WITH_AES_128_CBC_SHA256 */
	{ 0x003F, 0, "dh-rsa", 0, LN_aes_128_cbc, LN_sha256, NULL }, /* TLS_DH_RSA_WITH_AES_128_CBC_SHA256 */
	{ 0x0040, 0, "dhe-dss", 0, LN_aes_128_cbc, LN_sha256, NULL }, /* TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 */
	/* RFC 4132 */
	{ 0x0041, 0, LN_rsa, 0, LN_camellia_128_cbc, LN_sha1, NULL }, /* TLS_RSA_WITH_CAMELLIA_128_CBC_SHA */
	{ 0x0042, 0, "dh-dss", 0, LN_camellia_128_cbc, LN_sha1, NULL }, /* TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA */
	{ 0x0043, 0, "dh-rsa", 0, LN_camellia_128_cbc, LN_sha1, NULL }, /* TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA */
	{ 0x0044, 0, "dhe-dss", 0, LN_camellia_128_cbc, LN_sha1, NULL }, /* TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA */
	{ 0x0045, 0, "dhe-rsa", 0, LN_camellia_128_cbc, LN_sha1, NULL }, /* TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA */
	{ 0x0046, 0, "dh-anon", 0, LN_camellia_128_cbc, LN_sha1, NULL }, /* TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA */
	/* 0x00,0x60-66 Reserved to avoid conflicts with widely deployed implementations  */
	/* --- ??? --- */
	{ 0x0060, 0, "rsa-export1024", 56, LN_rc4, LN_md5, NULL }, /* TLS_RSA_EXPORT1024_WITH_RC4_56_MD5 */
	{ 0x0061, 0, "rsa-export1024", 56, LN_rc2_cbc, LN_md5, NULL }, /* TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 */
	/* draft-ietf-tls-56-bit-ciphersuites-01.txt */
	{ 0x0062, 0, "rsa-export1024", 56, LN_des_cbc, LN_sha1, NULL }, /* TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA */
	{ 0x0063, 0, "dhe-dss-export1024", 56, LN_des_cbc, LN_sha1, NULL }, /* TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA */
	{ 0x0064, 0, "rsa-export1024", 56, LN_rc4, LN_sha1, NULL }, /* TLS_RSA_EXPORT1024_WITH_RC4_56_SHA */
	{ 0x0065, 0, "dhe-dss-export1024", 56, LN_rc4, LN_sha1, NULL }, /* TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA */
	{ 0x0066, 0, "dhe-dss", 0, LN_rc4, LN_sha1, NULL }, /* TLS_DHE_DSS_WITH_RC4_128_SHA */
	/* --- ??? ---*/
	{ 0x0067, 0, "dhe-rsa", 0, LN_aes_128_cbc, LN_sha256, NULL }, /* TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 */
	{ 0x0068, 0, "dh-dss", 0, LN_aes_256_cbc, LN_sha256, NULL }, /* TLS_DH_DSS_WITH_AES_256_CBC_SHA256 */
	{ 0x0069, 0, "dh-rsa", 0, LN_aes_256_cbc, LN_sha256, NULL }, /* TLS_DH_RSA_WITH_AES_256_CBC_SHA256 */
	{ 0x006A, 0, "dhe-dss", 0, LN_aes_256_cbc, LN_sha256, NULL }, /* TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 */
	{ 0x006B, 0, "dhe-rsa", 0, LN_aes_256_cbc, LN_sha256, NULL }, /* TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 */
	{ 0x006C, 0, "dh-anon", 0, LN_aes_128_cbc, LN_sha256, NULL }, /* TLS_DH_anon_WITH_AES_128_CBC_SHA256 */
	{ 0x006D, 0, "dh-anon", 0, LN_aes_256_cbc, LN_sha256, NULL }, /* TLS_DH_anon_WITH_AES_256_CBC_SHA256 */
	/* draft-chudov-cryptopro-cptls-04.txt */
	{ 0x0080, 0, "gostr341094", 0, "28147-cnt", "imit", NULL }, /* TLS_GOSTR341094_WITH_28147_CNT_IMIT */
	{ 0x0081, 0, "gostr341001", 0, "28147-cnt", "imit", NULL }, /* TLS_GOSTR341001_WITH_28147_CNT_IMIT */
	{ 0x0082, 0, "gostr341094", 0, "null", "gostr3411", NULL }, /* TLS_GOSTR341094_WITH_NULL_GOSTR3411 */
	{ 0x0083, 0, "gostr341001", 0, "null", "gostr3411", NULL }, /* TLS_GOSTR341001_WITH_NULL_GOSTR3411 */
	/* RFC 4132 */
	{ 0x0084, 0, LN_rsa, 0, LN_camellia_256_cbc, LN_sha1, NULL }, /* TLS_RSA_WITH_CAMELLIA_256_CBC_SHA */
	{ 0x0085, 0, "dh-dss", 0, LN_camellia_256_cbc, LN_sha1, NULL }, /* TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA */
	{ 0x0086, 0, "dh-rsa", 0, LN_camellia_256_cbc, LN_sha1, NULL }, /* TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA */
	{ 0x0087, 0, "dhe-dss", 0, LN_camellia_256_cbc, LN_sha1, NULL }, /* TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA */
	{ 0x0088, 0, "dhe-rsa", 0, LN_camellia_256_cbc, LN_sha1, NULL }, /* TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA */
	{ 0x0089, 0, "dh-anon", 0, LN_camellia_256_cbc, LN_sha1, NULL }, /* TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA */
	/* RFC 4279 */
	{ 0x008A, 0, "psk", 0, LN_rc4, LN_sha1, NULL }, /* TLS_PSK_WITH_RC4_128_SHA */
	{ 0x008B, 0, "psk", 0, LN_des_ede3_cbc, LN_sha1, NULL }, /* TLS_PSK_WITH_3DES_EDE_CBC_SHA */
	{ 0x008C, 0, "psk", 0, LN_aes_128_cbc, LN_sha1, NULL }, /* TLS_PSK_WITH_AES_128_CBC_SHA */
	{ 0x008D, 0, "psk", 0, LN_aes_256_cbc, LN_sha1, NULL }, /* TLS_PSK_WITH_AES_256_CBC_SHA */
	{ 0x008E, 0, "dhe-psk", 0, LN_rc4, LN_sha1, NULL }, /* TLS_DHE_PSK_WITH_RC4_128_SHA */
	{ 0x008F, 0, "dhe-psk", 0, LN_des_ede3_cbc, LN_sha1, NULL }, /* TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA */
	{ 0x0090, 0, "dhe-psk", 0, LN_aes_128_cbc, LN_sha1, NULL }, /* TLS_DHE_PSK_WITH_AES_128_CBC_SHA */
	{ 0x0091, 0, "dhe-psk", 0, LN_aes_256_cbc, LN_sha1, NULL }, /* TLS_DHE_PSK_WITH_AES_256_CBC_SHA */
	{ 0x0092, 0, "rsa-psk", 0, LN_rc4, LN_sha1, NULL }, /* TLS_RSA_PSK_WITH_RC4_128_SHA */
	{ 0x0093, 0, "rsa-psk", 0, LN_des_ede3_cbc, LN_sha1, NULL }, /* TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA */
	{ 0x0094, 0, "rsa-psk", 0, LN_aes_128_cbc, LN_sha1, NULL }, /* TLS_RSA_PSK_WITH_AES_128_CBC_SHA */
	{ 0x0095, 0, "rsa-psk", 0, LN_aes_256_cbc, LN_sha1, NULL }, /* TLS_RSA_PSK_WITH_AES_256_CBC_SHA */
	/* RFC 4162 */
	{ 0x0096, 0, LN_rsa, 0, LN_seed_cbc, LN_sha1, NULL }, /* TLS_RSA_WITH_SEED_CBC_SHA */
	{ 0x0097, 0, "dh-dss", 0, LN_seed_cbc, LN_sha1, NULL }, /* TLS_DH_DSS_WITH_SEED_CBC_SHA */
	{ 0x0098, 0, "dh-rsa", 0, LN_seed_cbc, LN_sha1, NULL }, /* TLS_DH_RSA_WITH_SEED_CBC_SHA */
	{ 0x0099, 0, "dhe-dss", 0, LN_seed_cbc, LN_sha1, NULL }, /* TLS_DHE_DSS_WITH_SEED_CBC_SHA */
	{ 0x009A, 0, "dhe-rsa", 0, LN_seed_cbc, LN_sha1, NULL }, /* TLS_DHE_RSA_WITH_SEED_CBC_SHA */
	{ 0x009B, 0, "dh-anon", 0, LN_seed_cbc, LN_sha1, NULL }, /* TLS_DH_anon_WITH_SEED_CBC_SHA */
	/* RFC 5288 */
	{ 0x009C, 0, LN_rsa, 0, LN_aes_128_gcm, LN_sha256, NULL }, /* TLS_RSA_WITH_AES_128_GCM_SHA256 */
	{ 0x009D, 0, LN_rsa, 0, LN_aes_256_gcm, LN_sha384, NULL }, /* TLS_RSA_WITH_AES_256_GCM_SHA384 */
	{ 0x009E, 0, "dhe-rsa", 0, LN_aes_128_gcm, LN_sha256, NULL }, /* TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 */
	{ 0x009F, 0, "dhe-rsa", 0, LN_aes_256_gcm, LN_sha384, NULL }, /* TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 */
	{ 0x00A0, 0, "dh-rsa", 0, LN_aes_128_gcm, LN_sha256, NULL }, /* TLS_DH_RSA_WITH_AES_128_GCM_SHA256 */
	{ 0x00A1, 0, "dh-rsa", 0, LN_aes_256_gcm, LN_sha384, NULL }, /* TLS_DH_RSA_WITH_AES_256_GCM_SHA384 */
	{ 0x00A2, 0, "dhe-dss", 0, LN_aes_128_gcm, LN_sha256, NULL }, /* TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 */
	{ 0x00A3, 0, "dhe-dss", 0, LN_aes_256_gcm, LN_sha384, NULL }, /* TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 */
	{ 0x00A4, 0, "dh-dss", 0, LN_aes_128_gcm, LN_sha256, NULL }, /* TLS_DH_DSS_WITH_AES_128_GCM_SHA256 */
	{ 0x00A5, 0, "dh-dss", 0, LN_aes_256_gcm, LN_sha384, NULL }, /* TLS_DH_DSS_WITH_AES_256_GCM_SHA384 */
	{ 0x00A6, 0, "dh-anon", 0, LN_aes_128_gcm, LN_sha256, NULL }, /* TLS_DH_anon_WITH_AES_128_GCM_SHA256 */
	{ 0x00A7, 0, "dh-anon", 0, LN_aes_256_gcm, LN_sha384, NULL }, /* TLS_DH_anon_WITH_AES_256_GCM_SHA384 */
	/* RFC 5487 */
	{ 0x00A8, 0, "psk", 0, LN_aes_128_gcm, LN_sha256, NULL }, /* TLS_PSK_WITH_AES_128_GCM_SHA256 */
	{ 0x00A9, 0, "psk", 0, LN_aes_256_gcm, LN_sha384, NULL }, /* TLS_PSK_WITH_AES_256_GCM_SHA384 */
	{ 0x00AA, 0, "dhe-psk", 0, LN_aes_128_gcm, LN_sha256, NULL }, /* TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 */
	{ 0x00AB, 0, "dhe-psk", 0, LN_aes_256_gcm, LN_sha384, NULL }, /* TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 */
	{ 0x00AC, 0, "rsa-psk", 0, LN_aes_128_gcm, LN_sha256, NULL }, /* TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 */
	{ 0x00AD, 0, "rsa-psk", 0, LN_aes_256_gcm, LN_sha384, NULL }, /* TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 */
	{ 0x00AE, 0, "psk", 0, LN_aes_128_cbc, LN_sha256, NULL }, /* TLS_PSK_WITH_AES_128_CBC_SHA256 */
	{ 0x00AF, 0, "psk", 0, LN_aes_256_cbc, LN_sha384, NULL }, /* TLS_PSK_WITH_AES_256_CBC_SHA384 */
	{ 0x00B0, 0, "psk", 0, "null", LN_sha256, NULL }, /* TLS_PSK_WITH_NULL_SHA256 */
	{ 0x00B1, 0, "psk", 0, "null", LN_sha384, NULL }, /* TLS_PSK_WITH_NULL_SHA384 */
	{ 0x00B2, 0, "dhe-psk", 0, LN_aes_128_cbc, LN_sha256, NULL }, /* TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 */
	{ 0x00B3, 0, "dhe-psk", 0, LN_aes_256_cbc, LN_sha384, NULL }, /* TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 */
	{ 0x00B4, 0, "dhe-psk", 0, "null", LN_sha256, NULL }, /* TLS_DHE_PSK_WITH_NULL_SHA256 */
	{ 0x00B5, 0, "dhe-psk", 0, "null", LN_sha384, NULL }, /* TLS_DHE_PSK_WITH_NULL_SHA384 */
	{ 0x00B6, 0, "rsa-psk", 0, LN_aes_128_cbc, LN_sha256, NULL }, /* TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 */
	{ 0x00B7, 0, "rsa-psk", 0, LN_aes_256_cbc, LN_sha384, NULL }, /* TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 */
	{ 0x00B8, 0, "rsa-psk", 0, "null", LN_sha256, NULL }, /* TLS_RSA_PSK_WITH_NULL_SHA256 */
	{ 0x00B9, 0, "rsa-psk", 0, "null", LN_sha384, NULL }, /* TLS_RSA_PSK_WITH_NULL_SHA384 */
	/* From RFC 5932 */
	{ 0x00BA, 0, LN_rsa, 0, LN_camellia_128_cbc, LN_sha256, NULL }, /* TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
	{ 0x00BB, 0, "dh-dss", 0, LN_camellia_128_cbc, LN_sha256, NULL }, /* TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 */
	{ 0x00BC, 0, "dh-rsa", 0, LN_camellia_128_cbc, LN_sha256, NULL }, /* TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
	{ 0x00BD, 0, "dhe-dss", 0, LN_camellia_128_cbc, LN_sha256, NULL }, /* TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 */
	{ 0x00BE, 0, "dhe-rsa", 0, LN_camellia_128_cbc, LN_sha256, NULL }, /* TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
	{ 0x00BF, 0, "dh-anon", 0, LN_camellia_128_cbc, LN_sha256, NULL }, /* TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 */
	{ 0x00C0, 0, LN_rsa, 0, LN_camellia_256_cbc, LN_sha256, NULL }, /* TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 */
	{ 0x00C1, 0, "dh-dss", 0, LN_camellia_256_cbc, LN_sha256, NULL }, /* TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 */
	{ 0x00C2, 0, "dh-rsa", 0, LN_camellia_256_cbc, LN_sha256, NULL }, /* TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 */
	{ 0x00C3, 0, "dhe-dss", 0, LN_camellia_256_cbc, LN_sha256, NULL }, /* TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 */
	{ 0x00C4, 0, "dhe-rsa", 0, LN_camellia_256_cbc, LN_sha256, NULL }, /* TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 */
	{ 0x00C5, 0, "dh-anon", 0, LN_camellia_256_cbc, LN_sha256, NULL }, /* TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 */
	/* 0x00,0xC6-FE Unassigned  */
	/* From RFC 5746 */
	{ 0x00FF, 0, "empty", 0, SN_info, "scsv", NULL }, /* TLS_EMPTY_RENEGOTIATION_INFO_SCSV */
	/* From draft-bmoeller-tls-downgrade-scsv-02 */
	{ 0x5600, 0, "fallback", 0, "", "scsv", NULL }, /* TLS_FALLBACK_SCSV */
	/* From RFC 4492 */
	{ 0xc001, 0, "ecdh-ecdsa", 0, "null", LN_sha1, NULL }, /* TLS_ECDH_ECDSA_WITH_NULL_SHA */
	{ 0xc002, 0, "ecdh-ecdsa", 0, LN_rc4, LN_sha1, NULL }, /* TLS_ECDH_ECDSA_WITH_RC4_128_SHA */
	{ 0xc003, 0, "ecdh-ecdsa", 0, LN_des_ede3_cbc, LN_sha1, NULL }, /* TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA */
	{ 0xc004, 0, "ecdh-ecdsa", 0, LN_aes_128_cbc, LN_sha1, NULL }, /* TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA */
	{ 0xc005, 0, "ecdh-ecdsa", 0, LN_aes_256_cbc, LN_sha1, NULL }, /* TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA */
	{ 0xc006, 0, "ecdhe-ecdsa", 0, "null", LN_sha1, NULL }, /* TLS_ECDHE_ECDSA_WITH_NULL_SHA */
	{ 0xc007, 0, "ecdhe-ecdsa", 0, LN_rc4, LN_sha1, NULL }, /* TLS_ECDHE_ECDSA_WITH_RC4_128_SHA */
	{ 0xc008, 0, "ecdhe-ecdsa", 0, LN_des_ede3_cbc, LN_sha1, NULL }, /* TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA */
	{ 0xc009, 0, "ecdhe-ecdsa", 0, LN_aes_128_cbc, LN_sha1, NULL }, /* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA */
	{ 0xc00a, 0, "ecdhe-ecdsa", 0, LN_aes_256_cbc, LN_sha1, NULL }, /* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA */
	{ 0xc00b, 0, "ecdh-rsa", 0, "null", LN_sha1, NULL }, /* TLS_ECDH_RSA_WITH_NULL_SHA */
	{ 0xc00c, 0, "ecdh-rsa", 0, LN_rc4, LN_sha1, NULL }, /* TLS_ECDH_RSA_WITH_RC4_128_SHA */
	{ 0xc00d, 0, "ecdh-rsa", 0, LN_des_ede3_cbc, LN_sha1, NULL }, /* TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA */
	{ 0xc00e, 0, "ecdh-rsa", 0, LN_aes_128_cbc, LN_sha1, NULL }, /* TLS_ECDH_RSA_WITH_AES_128_CBC_SHA */
	{ 0xc00f, 0, "ecdh-rsa", 0, LN_aes_256_cbc, LN_sha1, NULL }, /* TLS_ECDH_RSA_WITH_AES_256_CBC_SHA */
	{ 0xc010, 0, "ecdhe-rsa", 0, "null", LN_sha1, NULL }, /* TLS_ECDHE_RSA_WITH_NULL_SHA */
	{ 0xc011, 0, "ecdhe-rsa", 0, LN_rc4, LN_sha1, NULL }, /* TLS_ECDHE_RSA_WITH_RC4_128_SHA */
	{ 0xc012, 0, "ecdhe-rsa", 0, LN_des_ede3_cbc, LN_sha1, NULL }, /* TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA */
	{ 0xc013, 0, "ecdhe-rsa", 0, LN_aes_128_cbc, LN_sha1, NULL }, /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA */
	{ 0xc014, 0, "ecdhe-rsa", 0, LN_aes_256_cbc, LN_sha1, NULL }, /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA */
	{ 0xc015, 0, "ecdh-anon", 0, "null", LN_sha1, NULL }, /* TLS_ECDH_anon_WITH_NULL_SHA */
	{ 0xc016, 0, "ecdh-anon", 0, LN_rc4, LN_sha1, NULL }, /* TLS_ECDH_anon_WITH_RC4_128_SHA */
	{ 0xc017, 0, "ecdh-anon", 0, LN_des_ede3_cbc, LN_sha1, NULL }, /* TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA */
	{ 0xc018, 0, "ecdh-anon", 0, LN_aes_128_cbc, LN_sha1, NULL }, /* TLS_ECDH_anon_WITH_AES_128_CBC_SHA */
	{ 0xc019, 0, "ecdh-anon", 0, LN_aes_256_cbc, LN_sha1, NULL }, /* TLS_ECDH_anon_WITH_AES_256_CBC_SHA */
	/* RFC 5054 */
	{ 0xC01A, 0, "srp-sha", 0, LN_des_ede3_cbc, LN_sha1, NULL }, /* TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA */
	{ 0xC01B, 0, "srp-sha-rsa", 0, LN_des_ede3_cbc, LN_sha1, NULL }, /* TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA */
	{ 0xC01C, 0, "srp-sha-dss", 0, LN_des_ede3_cbc, LN_sha1, NULL }, /* TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA */
	{ 0xC01D, 0, "srp-sha", 0, LN_aes_128_cbc, LN_sha1, NULL }, /* TLS_SRP_SHA_WITH_AES_128_CBC_SHA */
	{ 0xC01E, 0, "srp-sha-rsa", 0, LN_aes_128_cbc, LN_sha1, NULL }, /* TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA */
	{ 0xC01F, 0, "srp-sha-dss", 0, LN_aes_128_cbc, LN_sha1, NULL }, /* TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA */
	{ 0xC020, 0, "srp-sha", 0, LN_aes_256_cbc, LN_sha1, NULL }, /* TLS_SRP_SHA_WITH_AES_256_CBC_SHA */
	{ 0xC021, 0, "srp-sha-rsa", 0, LN_aes_256_cbc, LN_sha1, NULL }, /* TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA */
	{ 0xC022, 0, "srp-sha-dss", 0, LN_aes_256_cbc, LN_sha1, NULL }, /* TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA */
	/* RFC 5589 */
	{ 0xC023, 0, "ecdhe-ecdsa", 0, LN_aes_128_cbc, LN_sha256, NULL }, /* TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 */
	{ 0xC024, 0, "ecdhe-ecdsa", 0, LN_aes_256_cbc, LN_sha384, NULL }, /* TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 */
	{ 0xC025, 0, "ecdh-ecdsa", 0, LN_aes_128_cbc, LN_sha256, NULL }, /* TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 */
	{ 0xC026, 0, "ecdh-ecdsa", 0, LN_aes_256_cbc, LN_sha384, NULL }, /* TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 */
	{ 0xC027, 0, "ecdhe-rsa", 0, LN_aes_128_cbc, LN_sha256, NULL }, /* TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 */
	{ 0xC028, 0, "ecdhe-rsa", 0, LN_aes_256_cbc, LN_sha384, NULL }, /* TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 */
	{ 0xC029, 0, "ecdh-rsa", 0, LN_aes_128_cbc, LN_sha256, NULL }, /* TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 */
	{ 0xC02A, 0, "ecdh-rsa", 0, LN_aes_256_cbc, LN_sha384, NULL }, /* TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 */
	{ 0xC02B, 0, "ecdhe-ecdsa", 0, LN_aes_128_gcm, LN_sha256, NULL }, /* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */
	{ 0xC02C, 0, "ecdhe-ecdsa", 0, LN_aes_256_gcm, LN_sha384, NULL }, /* TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 */
	{ 0xC02D, 0, "ecdh-ecdsa", 0, LN_aes_128_gcm, LN_sha256, NULL }, /* TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 */
	{ 0xC02E, 0, "ecdh-ecdsa", 0, LN_aes_256_gcm, LN_sha384, NULL }, /* TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 */
	{ 0xC02F, 0, "ecdhe-rsa", 0, LN_aes_128_gcm, LN_sha256, NULL }, /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
	{ 0xC030, 0, "ecdhe-rsa", 0, LN_aes_256_gcm, LN_sha384, NULL }, /* TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 */
	{ 0xC031, 0, "ecdh-rsa", 0, LN_aes_128_gcm, LN_sha256, NULL }, /* TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 */
	{ 0xC032, 0, "ecdh-rsa", 0, LN_aes_256_gcm, LN_sha384, NULL }, /* TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 */
	/* RFC 5489 */
	{ 0xC033, 0, "ecdhe-psk", 0, LN_rc4, LN_sha1, NULL }, /* TLS_ECDHE_PSK_WITH_RC4_128_SHA */
	{ 0xC034, 0, "ecdhe-psk", 0, LN_des_ede3_cbc, LN_sha1, NULL }, /* TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA */
	{ 0xC035, 0, "ecdhe-psk", 0, LN_aes_128_cbc, LN_sha1, NULL }, /* TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA */
	{ 0xC036, 0, "ecdhe-psk", 0, LN_aes_256_cbc, LN_sha1, NULL }, /* TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA */
	{ 0xC037, 0, "ecdhe-psk", 0, LN_aes_128_cbc, LN_sha256, NULL }, /* TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 */
	{ 0xC038, 0, "ecdhe-psk", 0, LN_aes_256_cbc, LN_sha384, NULL }, /* TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 */
	{ 0xC039, 0, "ecdhe-psk", 0, "null", LN_sha1, NULL }, /* TLS_ECDHE_PSK_WITH_NULL_SHA */
	{ 0xC03A, 0, "ecdhe-psk", 0, "null", LN_sha256, NULL }, /* TLS_ECDHE_PSK_WITH_NULL_SHA256 */
	{ 0xC03B, 0, "ecdhe-psk", 0, "null", LN_sha384, NULL }, /* TLS_ECDHE_PSK_WITH_NULL_SHA384 */
	/* RFC 6209 */
	{ 0xC03C, 0, LN_rsa, 0, "aria-128-cbc", LN_sha256, NULL }, /* TLS_RSA_WITH_ARIA_128_CBC_SHA256 */
	{ 0xC03D, 0, LN_rsa, 0, "aria-256-cbc", LN_sha384, NULL }, /* TLS_RSA_WITH_ARIA_256_CBC_SHA384 */
	{ 0xC03E, 0, "dh-dss", 0, "aria-128-cbc", LN_sha256, NULL }, /* TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 */
	{ 0xC03F, 0, "dh-dss", 0, "aria-256-cbc", LN_sha384, NULL }, /* TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 */
	{ 0xC040, 0, "dh-rsa", 0, "aria-128-cbc", LN_sha256, NULL }, /* TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 */
	{ 0xC041, 0, "dh-rsa", 0, "aria-256-cbc", LN_sha384, NULL }, /* TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 */
	{ 0xC042, 0, "dhe-dss", 0, "aria-128-cbc", LN_sha256, NULL }, /* TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 */
	{ 0xC043, 0, "dhe-dss", 0, "aria-256-cbc", LN_sha384, NULL }, /* TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 */
	{ 0xC044, 0, "dhe-rsa", 0, "aria-128-cbc", LN_sha256, NULL }, /* TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 */
	{ 0xC045, 0, "dhe-rsa", 0, "aria-256-cbc", LN_sha384, NULL }, /* TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 */
	{ 0xC046, 0, "dh-anon", 0, "aria-128-cbc", LN_sha256, NULL }, /* TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 */
	{ 0xC047, 0, "dh-anon", 0, "aria-256-cbc", LN_sha384, NULL }, /* TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 */
	{ 0xC048, 0, "ecdhe-ecdsa", 0, "aria-128-cbc", LN_sha256, NULL }, /* TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 */
	{ 0xC049, 0, "ecdhe-ecdsa", 0, "aria-256-cbc", LN_sha384, NULL }, /* TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 */
	{ 0xC04A, 0, "ecdh-ecdsa", 0, "aria-128-cbc", LN_sha256, NULL }, /* TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 */
	{ 0xC04B, 0, "ecdh-ecdsa", 0, "aria-256-cbc", LN_sha384, NULL }, /* TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 */
	{ 0xC04C, 0, "ecdhe-rsa", 0, "aria-128-cbc", LN_sha256, NULL }, /* TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 */
	{ 0xC04D, 0, "ecdhe-rsa", 0, "aria-256-cbc", LN_sha384, NULL }, /* TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 */
	{ 0xC04E, 0, "ecdh-rsa", 0, "aria-128-cbc", LN_sha256, NULL }, /* TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 */
	{ 0xC04F, 0, "ecdh-rsa", 0, "aria-256-cbc", LN_sha384, NULL }, /* TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 */
	{ 0xC050, 0, LN_rsa, 0, "aria-128-gcm", LN_sha256, NULL }, /* TLS_RSA_WITH_ARIA_128_GCM_SHA256 */
	{ 0xC051, 0, LN_rsa, 0, "aria-256-gcm", LN_sha384, NULL }, /* TLS_RSA_WITH_ARIA_256_GCM_SHA384 */
	{ 0xC052, 0, "dhe-rsa", 0, "aria-128-gcm", LN_sha256, NULL }, /* TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 */
	{ 0xC053, 0, "dhe-rsa", 0, "aria-256-gcm", LN_sha384, NULL }, /* TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 */
	{ 0xC054, 0, "dh-rsa", 0, "aria-128-gcm", LN_sha256, NULL }, /* TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 */
	{ 0xC055, 0, "dh-rsa", 0, "aria-256-gcm", LN_sha384, NULL }, /* TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 */
	{ 0xC056, 0, "dhe-dss", 0, "aria-128-gcm", LN_sha256, NULL }, /* TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 */
	{ 0xC057, 0, "dhe-dss", 0, "aria-256-gcm", LN_sha384, NULL }, /* TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 */
	{ 0xC058, 0, "dh-dss", 0, "aria-128-gcm", LN_sha256, NULL }, /* TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 */
	{ 0xC059, 0, "dh-dss", 0, "aria-256-gcm", LN_sha384, NULL }, /* TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 */
	{ 0xC05A, 0, "dh-anon", 0, "aria-128-gcm", LN_sha256, NULL }, /* TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 */
	{ 0xC05B, 0, "dh-anon", 0, "aria-256-gcm", LN_sha384, NULL }, /* TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 */
	{ 0xC05C, 0, "ecdhe-ecdsa", 0, "aria-128-gcm", LN_sha256, NULL }, /* TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 */
	{ 0xC05D, 0, "ecdhe-ecdsa", 0, "aria-256-gcm", LN_sha384, NULL }, /* TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 */
	{ 0xC05E, 0, "ecdh-ecdsa", 0, "aria-128-gcm", LN_sha256, NULL }, /* TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 */
	{ 0xC05F, 0, "ecdh-ecdsa", 0, "aria-256-gcm", LN_sha384, NULL }, /* TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 */
	{ 0xC060, 0, "ecdhe-rsa", 0, "aria-128-gcm", LN_sha256, NULL }, /* TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 */
	{ 0xC061, 0, "ecdhe-rsa", 0, "aria-256-gcm", LN_sha384, NULL }, /* TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 */
	{ 0xC062, 0, "ecdh-rsa", 0, "aria-128-gcm", LN_sha256, NULL }, /* TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 */
	{ 0xC063, 0, "ecdh-rsa", 0, "aria-256-gcm", LN_sha384, NULL }, /* TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 */
	{ 0xC064, 0, "psk", 0, "aria-128-cbc", LN_sha256, NULL }, /* TLS_PSK_WITH_ARIA_128_CBC_SHA256 */
	{ 0xC065, 0, "psk", 0, "aria-256-cbc", LN_sha384, NULL }, /* TLS_PSK_WITH_ARIA_256_CBC_SHA384 */
	{ 0xC066, 0, "dhe-psk", 0, "aria-128-cbc", LN_sha256, NULL }, /* TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 */
	{ 0xC067, 0, "dhe-psk", 0, "aria-256-cbc", LN_sha384, NULL }, /* TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 */
	{ 0xC068, 0, "rsa-psk", 0, "aria-128-cbc", LN_sha256, NULL }, /* TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 */
	{ 0xC069, 0, "rsa-psk", 0, "aria-256-cbc", LN_sha384, NULL }, /* TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 */
	{ 0xC06A, 0, "psk", 0, "aria-128-gcm", LN_sha256, NULL }, /* TLS_PSK_WITH_ARIA_128_GCM_SHA256 */
	{ 0xC06B, 0, "psk", 0, "aria-256-gcm", LN_sha384, NULL }, /* TLS_PSK_WITH_ARIA_256_GCM_SHA384 */
	{ 0xC06C, 0, "dhe-psk", 0, "aria-128-gcm", LN_sha256, NULL }, /* TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 */
	{ 0xC06D, 0, "dhe-psk", 0, "aria-256-gcm", LN_sha384, NULL }, /* TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 */
	{ 0xC06E, 0, "rsa-psk", 0, "aria-128-gcm", LN_sha256, NULL }, /* TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 */
	{ 0xC06F, 0, "rsa-psk", 0, "aria-256-gcm", LN_sha384, NULL }, /* TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 */
	{ 0xC070, 0, "ecdhe-psk", 0, "aria-128-cbc", LN_sha256, NULL }, /* TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 */
	{ 0xC071, 0, "ecdhe-psk", 0, "aria-256-cbc", LN_sha384, NULL }, /* TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 */
	/* RFC 6367 */
	{ 0xC072, 0, "ecdhe-ecdsa", 0, LN_camellia_128_cbc, LN_sha256, NULL }, /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 */
	{ 0xC073, 0, "ecdhe-ecdsa", 0, LN_camellia_256_cbc, LN_sha384, NULL }, /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 */
	{ 0xC074, 0, "ecdh-ecdsa", 0, LN_camellia_128_cbc, LN_sha256, NULL }, /* TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 */
	{ 0xC075, 0, "ecdh-ecdsa", 0, LN_camellia_256_cbc, LN_sha384, NULL }, /* TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 */
	{ 0xC076, 0, "ecdhe-rsa", 0, LN_camellia_128_cbc, LN_sha256, NULL }, /* TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
	{ 0xC077, 0, "ecdhe-rsa", 0, LN_camellia_256_cbc, LN_sha384, NULL }, /* TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 */
	{ 0xC078, 0, "ecdh-rsa", 0, LN_camellia_128_cbc, LN_sha256, NULL }, /* TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 */
	{ 0xC079, 0, "ecdh-rsa", 0, LN_camellia_256_cbc, LN_sha384, NULL }, /* TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 */
	{ 0xC07A, 0, LN_rsa, 0, "camellia-128-gcm", LN_sha256, NULL }, /* TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
	{ 0xC07B, 0, LN_rsa, 0, "camellia-256-gcm", LN_sha384, NULL }, /* TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
	{ 0xC07C, 0, "dhe-rsa", 0, "camellia-128-gcm", LN_sha256, NULL }, /* TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
	{ 0xC07D, 0, "dhe-rsa", 0, "camellia-256-gcm", LN_sha384, NULL }, /* TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
	{ 0xC07E, 0, "dh-rsa", 0, "camellia-128-gcm", LN_sha256, NULL }, /* TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
	{ 0xC07F, 0, "dh-rsa", 0, "camellia-256-gcm", LN_sha384, NULL }, /* TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
	{ 0xC080, 0, "dhe-dss", 0, "camellia-128-gcm", LN_sha256, NULL }, /* TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 */
	{ 0xC081, 0, "dhe-dss", 0, "camellia-256-gcm", LN_sha384, NULL }, /* TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 */
	{ 0xC082, 0, "dh-dss", 0, "camellia-128-gcm", LN_sha256, NULL }, /* TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 */
	{ 0xC083, 0, "dh-dss", 0, "camellia-256-gcm", LN_sha384, NULL }, /* TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 */
	{ 0xC084, 0, "dh-anon", 0, "camellia-128-gcm", LN_sha256, NULL }, /* TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 */
	{ 0xC085, 0, "dh-anon", 0, "camellia-256-gcm", LN_sha384, NULL }, /* TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 */
	{ 0xC086, 0, "ecdhe-ecdsa", 0, "camellia-128-gcm", LN_sha256, NULL }, /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 */
	{ 0xC087, 0, "ecdhe-ecdsa", 0, "camellia-256-gcm", LN_sha384, NULL }, /* TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 */
	{ 0xC088, 0, "ecdh-ecdsa", 0, "camellia-128-gcm", LN_sha256, NULL }, /* TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 */
	{ 0xC089, 0, "ecdh-ecdsa", 0, "camellia-256-gcm", LN_sha384, NULL }, /* TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 */
	{ 0xC08A, 0, "ecdhe-rsa", 0, "camellia-128-gcm", LN_sha256, NULL }, /* TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
	{ 0xC08B, 0, "ecdhe-rsa", 0, "camellia-256-gcm", LN_sha384, NULL }, /* TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
	{ 0xC08C, 0, "ecdh-rsa", 0, "camellia-128-gcm", LN_sha256, NULL }, /* TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 */
	{ 0xC08D, 0, "ecdh-rsa", 0, "camellia-256-gcm", LN_sha384, NULL }, /* TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 */
	{ 0xC08E, 0, "psk", 0, "camellia-128-gcm", LN_sha256, NULL }, /* TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 */
	{ 0xC08F, 0, "psk", 0, "camellia-256-gcm", LN_sha384, NULL }, /* TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 */
	{ 0xC090, 0, "dhe-psk", 0, "camellia-128-gcm", LN_sha256, NULL }, /* TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 */
	{ 0xC091, 0, "dhe-psk", 0, "camellia-256-gcm", LN_sha384, NULL }, /* TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 */
	{ 0xC092, 0, "rsa-psk", 0, "camellia-128-gcm", LN_sha256, NULL }, /* TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 */
	{ 0xC093, 0, "rsa-psk", 0, "camellia-256-gcm", LN_sha384, NULL }, /* TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 */
	{ 0xC094, 0, "psk", 0, LN_camellia_128_cbc, LN_sha256, NULL }, /* TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
	{ 0xC095, 0, "psk", 0, LN_camellia_256_cbc, LN_sha384, NULL }, /* TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
	{ 0xC096, 0, "dhe-psk", 0, LN_camellia_128_cbc, LN_sha256, NULL }, /* TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
	{ 0xC097, 0, "dhe-psk", 0, LN_camellia_256_cbc, LN_sha384, NULL }, /* TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
	{ 0xC098, 0, "rsa-psk", 0, LN_camellia_128_cbc, LN_sha256, NULL }, /* TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
	{ 0xC099, 0, "rsa-psk", 0, LN_camellia_256_cbc, LN_sha384, NULL }, /* TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
	{ 0xC09A, 0, "ecdhe-psk", 0, LN_camellia_128_cbc, LN_sha256, NULL }, /* TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 */
	{ 0xC09B, 0, "ecdhe-psk", 0, LN_camellia_256_cbc, LN_sha384, NULL }, /* TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 */
	/* RFC 6655 */
	{ 0xC09C, 0, LN_rsa, 0, LN_aes_128_ccm, "null", NULL }, /* TLS_RSA_WITH_AES_128_CCM */
	{ 0xC09D, 0, LN_rsa, 0, LN_aes_256_ccm, "null", NULL }, /* TLS_RSA_WITH_AES_256_CCM */
	{ 0xC09E, 0, "dhe-rsa", 0, LN_aes_128_ccm, "null", NULL }, /* TLS_DHE_RSA_WITH_AES_128_CCM */
	{ 0xC09F, 0, "dhe-rsa", 0, LN_aes_256_ccm, "null", NULL }, /* TLS_DHE_RSA_WITH_AES_256_CCM */
	{ 0xC0A0, 0, LN_rsa, 0, LN_aes_128_ccm, "null", (void*)8 }, /* TLS_RSA_WITH_AES_128_CCM_8 */
	{ 0xC0A1, 0, LN_rsa, 0, LN_aes_256_ccm, "null", (void*)8 }, /* TLS_RSA_WITH_AES_256_CCM_8 */
	{ 0xC0A2, 0, "dhe-rsa", 0, LN_aes_128_ccm, "null", (void*)8 }, /* TLS_DHE_RSA_WITH_AES_128_CCM_8 */
	{ 0xC0A3, 0, "dhe-rsa", 0, LN_aes_256_ccm, "null", (void*)8 }, /* TLS_DHE_RSA_WITH_AES_256_CCM_8 */
	{ 0xC0A4, 0, "psk", 0, LN_aes_128_ccm, "null", NULL }, /* TLS_PSK_WITH_AES_128_CCM */
	{ 0xC0A5, 0, "psk", 0, LN_aes_256_ccm, "null", NULL }, /* TLS_PSK_WITH_AES_256_CCM */
	{ 0xC0A6, 0, "dhe-psk", 0, LN_aes_128_ccm, "null", NULL }, /* TLS_DHE_PSK_WITH_AES_128_CCM */
	{ 0xC0A7, 0, "dhe-psk", 0, LN_aes_256_ccm, "null", NULL }, /* TLS_DHE_PSK_WITH_AES_256_CCM */
	{ 0xC0A8, 0, "psk", 0, LN_aes_128_ccm, "null", (void*)8 }, /* TLS_PSK_WITH_AES_128_CCM_8 */
	{ 0xC0A9, 0, "psk", 0, LN_aes_256_ccm, "null", (void*)8 }, /* TLS_PSK_WITH_AES_256_CCM_8 */
	{ 0xC0AA, 0, "psk-dhe", 0, LN_aes_128_ccm, "null", (void*)8 }, /* TLS_PSK_DHE_WITH_AES_128_CCM_8 */
	{ 0xC0AB, 0, "psk-dhe", 0, LN_aes_256_ccm, "null", (void*)8 }, /* TLS_PSK_DHE_WITH_AES_256_CCM_8 */
	/* RFC 7251 */
	{ 0xC0AC, 0, "ecdhe-ecdsa", 0, LN_aes_128_ccm, "null", NULL }, /* TLS_ECDHE_ECDSA_WITH_AES_128_CCM */
	{ 0xC0AD, 0, "ecdhe-ecdsa", 0, LN_aes_256_ccm, "null", NULL }, /* TLS_ECDHE_ECDSA_WITH_AES_256_CCM */
	{ 0xC0AE, 0, "ecdhe-ecdsa", 0, LN_aes_128_ccm, "null", (void*)8 }, /* TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 */
	{ 0xC0AF, 0, "ecdhe-ecdsa", 0, LN_aes_256_ccm, "null", (void*)8 }, /* TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 */
	/* http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305 */
	{ 0xCC13, 0, "ecdhe-rsa", 0, "chacha20-poly1305", LN_sha256, NULL }, /* TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */
	{ 0xCC14, 0, "ecdhe-ecdsa", 0, "chacha20-poly1305", LN_sha256, NULL }, /* TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 */
	{ 0xCC15, 0, "dhe-rsa", 0, "chacha20-poly1305", LN_sha256, NULL }, /* TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */
	/* http://tools.ietf.org/html/draft-josefsson-salsa20-tls */
	{ 0xE410, 0, LN_rsa, 0, "estream-salsa20", LN_sha1, NULL }, /* TLS_RSA_WITH_ESTREAM_SALSA20_SHA1 */
	{ 0xE411, 0, LN_rsa, 0, "salsa20", LN_sha1, NULL }, /* TLS_RSA_WITH_SALSA20_SHA1 */
	{ 0xE412, 0, "ecdhe-rsa", 0, "estream-salsa20", LN_sha1, NULL }, /* TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_SHA1 */
	{ 0xE413, 0, "ecdhe-rsa", 0, "salsa20", LN_sha1, NULL }, /* TLS_ECDHE_RSA_WITH_SALSA20_SHA1 */
	{ 0xE414, 0, "ecdhe-ecdsa", 0, "estream-salsa20", LN_sha1, NULL }, /* TLS_ECDHE_ECDSA_WITH_ESTREAM_SALSA20_SHA1 */
	{ 0xE415, 0, "ecdhe-ecdsa", 0, "salsa20", LN_sha1, NULL }, /* TLS_ECDHE_ECDSA_WITH_SALSA20_SHA1 */
	{ 0xE416, 0, "psk", 0, "estream-salsa20", LN_sha1, NULL }, /* TLS_PSK_WITH_ESTREAM_SALSA20_SHA1 */
	{ 0xE417, 0, "psk", 0, "salsa20", LN_sha1, NULL }, /* TLS_PSK_WITH_SALSA20_SHA1 */
	{ 0xE418, 0, "ecdhe-psk", 0, "estream-salsa20", LN_sha1, NULL }, /* TLS_ECDHE_PSK_WITH_ESTREAM_SALSA20_SHA1 */
	{ 0xE419, 0, "ecdhe-psk", 0, "salsa20", LN_sha1, NULL }, /* TLS_ECDHE_PSK_WITH_SALSA20_SHA1 */
	{ 0xE41A, 0, "rsa-psk", 0, "estream-salsa20", LN_sha1, NULL }, /* TLS_RSA_PSK_WITH_ESTREAM_SALSA20_SHA1 */
	{ 0xE41B, 0, "rsa-psk", 0, "salsa20", LN_sha1, NULL }, /* TLS_RSA_PSK_WITH_SALSA20_SHA1 */
	{ 0xE41C, 0, "dhe-psk", 0, "estream-salsa20", LN_sha1, NULL }, /* TLS_DHE_PSK_WITH_ESTREAM_SALSA20_SHA1 */
	{ 0xE41D, 0, "dhe-psk", 0, "salsa20", LN_sha1, NULL }, /* TLS_DHE_PSK_WITH_SALSA20_SHA1 */
	{ 0xE41E, 0, "dhe-rsa", 0, "estream-salsa20", LN_sha1, NULL }, /* TLS_DHE_RSA_WITH_ESTREAM_SALSA20_SHA1 */
	{ 0xE41F, 0, "dhe-rsa", 0, "salsa20", LN_sha1, NULL }, /* TLS_DHE_RSA_WITH_SALSA20_SHA1 */
	/* these from http://www.mozilla.org/projects/security/pki/nss/ssl/fips-ssl-ciphersuites.html */
	{ 0xfefe, 0, "rsa-fips", 0, LN_des_cbc, LN_sha1, NULL }, /* SSL_RSA_FIPS_WITH_DES_CBC_SHA */
	{ 0xfeff, 0, "rsa-fips", 0, LN_des_ede3_cbc, LN_sha1, NULL }, /* SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA */
	{ 0xffe0, 0, "rsa-fips", 0, LN_des_ede3_cbc, LN_sha1, NULL }, /* SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA */
	{ 0xffe1, 0, "rsa-fips", 0, LN_des_cbc, LN_sha1, NULL } /* SSL_RSA_FIPS_WITH_DES_CBC_SHA */
	/* note that ciphersuites 0xff00 - 0xffff are private */
};

static int compare_cipher_suites( const void* key, const void* elem )
{
	uint16_t id = *((uint16_t*)key);
	DSSL_CipherSuite* cs = (DSSL_CipherSuite*) elem;

	return id - cs->id;
}

DSSL_CipherSuite* DSSL_GetSSL3CipherSuite( uint16_t id )
{
	DEBUG_TRACE1( "=> GetSSL3CipherSuite(0x%x)\n", id );

	DSSL_CipherSuite* rslt = (DSSL_CipherSuite*) bsearch( &id, ssl3suites, 
			sizeof(ssl3suites)/sizeof(ssl3suites[0]), sizeof(ssl3suites[0]),
			compare_cipher_suites );
	if(!rslt) 
	{
		unsigned i;
		for(i = 0; i < sizeof(ssl3suites)/sizeof(ssl3suites[0]); i++) 
		{
			if( ssl3suites[i].id == id ) 
			{
				rslt = &ssl3suites[i];
				break;
			}
		}
	}
	return rslt;
}

static DSSL_CipherSuite ssl2suites[] = 
{
	{ 0x01, SSL2_VERSION, SSL_KEX_RSA, 0, "RC4", "MD5" },
	{ 0x02, SSL2_VERSION, SSL_KEX_RSA, 40, "RC4", "MD5" },
	{ 0x03, SSL2_VERSION, SSL_KEX_RSA, 0, "RC2", "MD5" },
	{ 0x04, SSL2_VERSION, SSL_KEX_RSA, 40, "RC2", "MD5" },
	{ 0x05, SSL2_VERSION, SSL_KEX_RSA, 0, "IDEA", "MD5" },
	{ 0x06, SSL2_VERSION, SSL_KEX_RSA, 0, "DES", "MD5" },
	{ 0x07, SSL2_VERSION, SSL_KEX_RSA, 0, SN_des_ede3_cbc, "MD5" }
};


int DSSL_ConvertSSL2CipherSuite( u_char cs[3], uint16_t* pcs )
{
	_ASSERT( pcs );

	if(cs[0] > 0x07 ) return NM_ERROR( DSSL_E_SSL2_UNKNOWN_CIPHER_KIND );
	if(cs[1] != 0 ) return NM_ERROR( DSSL_E_SSL2_UNKNOWN_CIPHER_KIND );
	switch(cs[2])
	{
	case 0x80: if( cs[0] > 0x05 ) { return NM_ERROR( DSSL_E_SSL2_UNKNOWN_CIPHER_KIND ); } break;
	case 0x40: if( cs[0] != 0x06 ) { return NM_ERROR( DSSL_E_SSL2_UNKNOWN_CIPHER_KIND ); } break;
	case 0xC0: if( cs[0] != 0x07 ) { return NM_ERROR( DSSL_E_SSL2_UNKNOWN_CIPHER_KIND ); } break;
	default: return NM_ERROR( DSSL_E_SSL2_UNKNOWN_CIPHER_KIND );
	}

	_ASSERT( cs[0] <= sizeof(ssl2suites)/sizeof(ssl2suites[0]) );

	*pcs = cs[0];

	return DSSL_RC_OK;
}


DSSL_CipherSuite* DSSL_GetSSL2CipherSuite( uint16_t id )
{
	if( id == 0 || id > sizeof(ssl2suites)/sizeof(ssl2suites[0]) )
	{
		_ASSERT( FALSE );
		return NULL;
	}

	return &ssl2suites[id-1];
}


int DSSL_CipherSuiteExportable( DSSL_CipherSuite* ss )
{
	return ss->export_key_bits != 0;
}
