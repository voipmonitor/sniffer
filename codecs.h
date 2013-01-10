#define PAYLOAD_PCMU 0
#define PAYLOAD_GSM 3
#define PAYLOAD_G723 4
#define PAYLOAD_PCMA 8
#define PAYLOAD_G729 18
#define PAYLOAD_ILBC 97
#define PAYLOAD_SPEEX 98
#define PAYLOAD_SILK 301
#define PAYLOAD_SILK8 302
#define PAYLOAD_SILK12 303
#define PAYLOAD_SILK16 304
#define PAYLOAD_SILK24 305
#define PAYLOAD_ISAC 306
#define PAYLOAD_ISAC16 307
#define PAYLOAD_ISAC32 308

#define USE_ILBC_ENHANCER	0
#define ILBC_MS			30
/* #define ILBC_MS                      20 */

#define ILBC_FRAME_LEN	50      /* apparently... */
#define ILBC_SAMPLES	240     /* 30ms at 8000 hz */

#define GSM_SAMPLES     160
#define GSM_FRAME_LEN   33
#define MSGSM_FRAME_LEN 65

#define BUFFER_SAMPLES	8000

