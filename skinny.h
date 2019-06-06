#ifndef SKINNY_H
#define SKINNY_H


#define SKINNY_PAYLOAD_G711ALAW64K              0x00002 /* audio */
#define SKINNY_PAYLOAD_G711ALAW56K              0x00003 /* audio */
#define SKINNY_PAYLOAD_G711ULAW64K              0x00004 /* audio */
#define SKINNY_PAYLOAD_G711ULAW56K              0x00005 /* audio */
#define SKINNY_PAYLOAD_G722_64K                 0x00006 /* audio */
#define SKINNY_PAYLOAD_G722_56K                 0x00007 /* audio */
#define SKINNY_PAYLOAD_G722_48K                 0x00008 /* audio */
#define SKINNY_PAYLOAD_G7231                    0x00009 /* audio */
#define SKINNY_PAYLOAD_G728                     0x0000a /* audio */
#define SKINNY_PAYLOAD_G729                     0x0000b /* audio */
#define SKINNY_PAYLOAD_G729ANNEXA               0x0000c /* audio */
#define SKINNY_PAYLOAD_G729ANNEXB               0x0000f /* audio */
#define SKINNY_PAYLOAD_G729ANNEXAWANNEXB        0x00010 /* audio */
#define SKINNY_PAYLOAD_GSM_FULL_RATE            0x00012 /* audio */
#define SKINNY_PAYLOAD_GSM_HALF_RATE            0x00013 /* audio */
#define SKINNY_PAYLOAD_GSM_ENHANCED_FULL_RATE   0x00014 /* audio */
#define SKINNY_PAYLOAD_WIDE_BAND_256K           0x00019 /* audio */
#define SKINNY_PAYLOAD_DATA64                   0x00020 /* audio */
#define SKINNY_PAYLOAD_DATA56                   0x00021 /* audio */
#define SKINNY_PAYLOAD_G7221_32K                0x00028 /* audio */
#define SKINNY_PAYLOAD_G7221_24K                0x00029 /* audio */
#define SKINNY_PAYLOAD_AAC                      0x0002a /* audio */
#define SKINNY_PAYLOAD_MP4ALATM_128             0x0002b /* audio */
#define SKINNY_PAYLOAD_MP4ALATM_64              0x0002c /* audio */
#define SKINNY_PAYLOAD_MP4ALATM_56              0x0002d /* audio */
#define SKINNY_PAYLOAD_MP4ALATM_48              0x0002e /* audio */
#define SKINNY_PAYLOAD_MP4ALATM_32              0x0002f /* audio */
#define SKINNY_PAYLOAD_MP4ALATM_24              0x00030 /* audio */
#define SKINNY_PAYLOAD_MP4ALATM_NA              0x00031 /* audio */
#define SKINNY_PAYLOAD_GSM                      0x00050 /* audio */
#define SKINNY_PAYLOAD_G726_32K                 0x00052 /* audio */
#define SKINNY_PAYLOAD_G726_24K                 0x00053 /* audio */
#define SKINNY_PAYLOAD_G726_16K                 0x00054 /* audio */
#define SKINNY_PAYLOAD_ILBC                     0x00056 /* audio */
#define SKINNY_PAYLOAD_ISAC                     0x00059 /* audio */
#define SKINNY_PAYLOAD_OPUS                     0x0005a /* audio */
#define SKINNY_PAYLOAD_AMR                      0x00061 /* audio */
#define SKINNY_PAYLOAD_AMR_WB                   0x00062 /* audio */
#define SKINNY_PAYLOAD_H261                     0x00064 /* video */
#define SKINNY_PAYLOAD_H263                     0x00065 /* video */
#define SKINNY_PAYLOAD_VIEO                     0x00066 /* video */
#define SKINNY_PAYLOAD_H264                     0x00067 /* video */
#define SKINNY_PAYLOAD_H264_SVC                 0x00068 /* video */
#define SKINNY_PAYLOAD_T120                     0x00069 /* video */
#define SKINNY_PAYLOAD_H224                     0x0006a /* video */
#define SKINNY_PAYLOAD_T38FAX                   0x0006b /* video */
#define SKINNY_PAYLOAD_TOTE                     0x0006c /* video */
#define SKINNY_PAYLOAD_H265                     0x0006d /* video */
#define SKINNY_PAYLOAD_H264_UC                  0x0006e /* video */
#define SKINNY_PAYLOAD_XV150_MR_711U            0x0006f /* video */
#define SKINNY_PAYLOAD_NSE_VBD_711U             0x00070 /* video */
#define SKINNY_PAYLOAD_XV150_MR_729A            0x00071 /* video */
#define SKINNY_PAYLOAD_NSE_VBD_729A             0x00072 /* video */
#define SKINNY_PAYLOAD_H264_FEC                 0x00073 /* video */
#define SKINNY_PAYLOAD_CLEAR_CHAN               0x00078 /* data */
#define SKINNY_PAYLOAD_UNIVERSAL_XCODER         0x000de /* data */
#define SKINNY_PAYLOAD_RFC2833_DYNPAYLOAD       0x00101 /* data */
#define SKINNY_PAYLOAD_PASSTHROUGH              0x00102 /* data */
#define SKINNY_PAYLOAD_DYNAMIC_PAYLOAD_PASSTHRU 0x00103 /* data */
#define SKINNY_PAYLOAD_DTMF_OOB                 0x00104 /* data */
#define SKINNY_PAYLOAD_INBAND_DTMF_RFC2833      0x00105 /* data */
#define SKINNY_PAYLOAD_CFB_TONES                0x00106 /* data */
#define SKINNY_PAYLOAD_NOAUDIO                  0x0012b /* data */
#define SKINNY_PAYLOAD_V150_LC_MODEMRELAY       0x0012c /* data */
#define SKINNY_PAYLOAD_V150_LC_SPRT             0x0012d /* data */
#define SKINNY_PAYLOAD_V150_LC_SSE              0x0012e /* data */
#define SKINNY_PAYLOAD_MAX                      0x0012f /* data */


void *handle_skinny(pcap_pkthdr *, const u_char *, vmIP, vmPort, vmIP, vmPort, char *, int, int,
		    pcap_t *handle, int dlt, int sensor_id, vmIP sensor_ip);

#endif
