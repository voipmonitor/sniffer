/* Martin Vit support@voipmonitor.org
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2.
*/

#ifndef RTP_H
#define RTP_H
#include <netinet/in.h>
#include <fstream>
#include <iostream>
#include "gzstream/gzstream.h"

//#include "jitterbuffer/asterisk/channel.h"
#include "jitterbuffer/asterisk/abstract_jb.h"

#define MAX_RTPMAP 30


using namespace std;

void burstr_calculate(struct ast_channel *chan, u_int32_t received, double *burstr, double *lossr);

/*

http://www.ietf.org/rfc/rfc3550.txt

The RTP header has the following format:

    0		   1		   2		   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |V=2|P|X|  CC   |M|     PT      |       sequence number	 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |			   timestamp			   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |	   synchronization source (SSRC) identifier	    |
   +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
   |	    contributing source (CSRC) identifiers	     |
   |			     ....			      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/


/*
   version (V): 2 bits
      This field identifies the version of RTP.  The version defined by
      this specification is two (2).  (The value 1 is used by the first
      draft version of RTP and the value 0 is used by the protocol
      initially implemented in the "vat" audio tool.)
*/

/*
   padding (P): 1 bit
      If the padding bit is set, the packet contains one or more
      additional padding octets at the end which are not part of the
      payload.  The last octet of the padding contains a count of how
      many padding octets should be ignored, including itself.  Padding
      may be needed by some encryption algorithms with fixed block sizes
      or for carrying several RTP packets in a lower-layer protocol data
      unit.
*/

/*
   extension (X): 1 bit
      If the extension bit is set, the fixed header MUST be followed by
      exactly one header extension, with a format defined in Section
      5.3.1.
*/

/*
   CSRC count (CC): 4 bits
      The CSRC count contains the number of CSRC identifiers that follow
      the fixed header.
*/
 
/*
   marker (M): 1 bit
      The interpretation of the marker is defined by a profile.  It is
      intended to allow significant events such as frame boundaries to
      be marked in the packet stream.  A profile MAY define additional
      marker bits or specify that there is no marker bit by changing the
      number of bits in the payload type field (see Section 5.3).
*/

/*
   payload type (PT): 7 bits
      This field identifies the format of the RTP payload and determines
      its interpretation by the application.  A profile MAY specify a
      default static mapping of payload type codes to payload formats.
      Additional payload type codes MAY be defined dynamically through
      non-RTP means (see Section 3).  A set of default mappings for
      audio and video is specified in the companion RFC 3551 [1].  An
      RTP source MAY change the payload type during a session, but this
      field SHOULD NOT be used for multiplexing separate media streams
      (see Section 5.2).

      A receiver MUST ignore packets with payload types that it does not
      understand.
*/

#define RTP_VERSION    2	//!< current protocol version 

#define RTP_SEQ_MOD (1<<16)
#define RTP_MAX_SDES 255	//!< maximum text length for SDES 

#define MIN_SEQUENTIAL 2
#define MAX_MISORDER 100
#define MAX_DROPOUT 3000

/**
 * This class implements operations on RTP strem
 */
class RTP {
       /* extension header */
       typedef struct {
	       u_int16_t profdef;
	       u_int16_t length; // length of extension in 32bits, this header exluded.
       } extension_hdr_t;
public: 
	u_int32_t ssrc;		//!< ssrc of this RTP class
	u_int32_t saddr;	//!< last source IP adress 
	ogzstream gfileGZ;	//!< file for storing packet statistics with GZIP compression
	ofstream gfile;		//!< file for storing packet statistics
	FILE *gfileRAW;         //!< file for storing RTP payload in RAW format
	char *gfileRAW_buffer;
	char gfilename[1024];	//!< file name of this file 
	char basefilename[1024];
	int rawiterator;	//!< iterator for raw file name 
	struct ast_channel *channel_fix1;
	struct ast_channel *channel_fix2;
	struct ast_channel *channel_adapt;
	struct ast_channel *channel_record;
	struct ast_frame *frame;
	int lastframetype;		//!< last packet sequence number
	int last_seq;		//!< last packet sequence number
	int packetization;	//!< packetization in millisenocds
	int last_packetization;	//!< last packetization in millisenocds
	int last_ts;		//!< last timestamp 
	int packetization_iterator;	
	int payload;
	int prev_payload;
	int codec;
	int rtpmap[MAX_RTPMAP];
	unsigned char* data;    //!< pointer to UDP payload
	int len;		//!< lenght of UDP payload
	unsigned char* payload_data;    //!< pointer to RTP payload
	int payload_len;	//!< lenght of RTP payload
	int ssrc_index;		//!< index 
	int iscaller;		//!< flag which indicates if RTP stream is part of caller or callee
	void *call_owner;	//!< which Call owns us
	int default_packetization;
	int sid;
	int prev_sid;

	struct stats_t {
		u_int32_t	d50;	//!< delay from 0 to 50
		u_int32_t	d70;
		u_int32_t	d90;
		u_int32_t	d120; 
		u_int32_t	d150; 
		u_int32_t	d200; 
		u_int32_t	d300;

		u_int32_t	slost[11];	//!< lost counts
		
		u_int32_t	received;	//!< overall received packets
		u_int32_t	lost;		//!< overall lost packets
		int		last_lost;	//!< last overall lost packepts
		long double 	avgjitter;
		long double 	maxjitter;
	} stats;

        /**
	* constructor which allocates and zeroing stats structure
	*
        */
	RTP();

        /**
	* destructor
	*
        */
	~RTP();

        /**
	 * @brief simulate jitter buffer
	 *
	 * Put packet to jitterbuffer associated to channel structure
	 *
	 * @param channel pointer to the channel structure which holds statistics and jitterbuffer data
	 *
        */
	void jitterbuffer(struct ast_channel *channel, int savePayload);

        /**
	 * @brief read RTP packet
	 *
	 * Used for reading RTP packet
	 *
	 * @param data pointer to the packet buffer
	 * @param datalen lenght of the buffer
	 * @param header header structure of the packet
	 * @param saddr source IP adress of the packet
	 *
        */
	void read(unsigned char* data, int len, struct pcap_pkthdr *header,  u_int32_t saddr, int seeninviteok);


        /**
	 * @brief fill RTP packet into structures
	 *
	 * Used for temporary operations on RTP packet
	 *
	 * @param data pointer to the packet buffer
	 * @param datalen lenght of the buffer
	 * @param header header structure of the packet
	 * @param saddr source IP adress of the packet
	 *
        */
	void fill(unsigned char* data, int len, struct pcap_pkthdr *header,  u_int32_t saddr);

	/**
	 * @brief get version
	 *
	 * this function gets version from rtp header
	 *
	 * @return padding RTP version
	*/
	const unsigned char getVersion() { return getHeader()->version; };
	
        /**
	 * @brief get sequence sumber
	 *
	 * this function gets sequence number from header of RTP packet
	 *
	 * @return sequence number
        */
	const u_int16_t getSeqNum() { return htons(getHeader()->sequence); };

        /**
	 * @brief get timestamp 
	 *
	 * this function gets timestamp from header of RTP packet
	 *
	 * @return number of seocnds since UNIX epoch
        */
	const u_int32_t getTimestamp() { return htonl(getHeader()->timestamp); };
	
        /**
	 * @brief get SSRC
	 *
	 * this function gets SSRC from header of RTP packet
	 *
	 * @return SSRC
        */
	const u_int32_t getSSRC() { return htonl(getHeader()->sources[0]); };

        /**
	 * @brief get Payload 
	 *
	 * this function gets Payload from header of RTP packet
	 *
	 * @return SSRC
        */
	const int getPayload() { return getHeader()->payload; };
        /**
	 * @brief get SSRC
	 *
	 * this function gets number of received packets
	 *
	 * @return received packets
        */
	const u_int32_t getReceived() { return s->received; };

        /**
	 * @brief get SSRC
	 *
	 * this function gets number of received packets
	 *
	 * @return received packets
	*/
	const int getMarker() { return getHeader()->marker; };

	/**
	 * @brief get padding
	 *
	 * this function gets padding bit from rtp header
	 *
	 * @return padding bit
	*/
	const unsigned char getPadding() { return getHeader()->padding; };
 
	 /**
	 * @brief get cc
	 *
	 * this function gets the number of CSRC identifiers that follow the fixed header.
	 *
	 * @return 4bits number (integer)
	*/
	const int getCC() { return getHeader()->cc; };
 
	 /**
	 * @brief get extension
	 *
	 * this function gets X, Extension. 1 bit.
	 *
	 * @return 1bit
	*/
	const int getExtension() { return getHeader()->extension; };
 
	 /**
	 * @brief get payload length
	 *
	 * this function gets length of payload 
	 *
	 * @return number of bytes of payload
	*/
	const unsigned int get_payload_len();

	 /**

	 * @brief flushes frames from jitterbuffer
	 *
	 * this function flushes all frames from jitterbuffer fixed implementation and writes it to raw files
        */
	void jitterbuffer_fixed_flush(struct ast_channel *channel);

	 /**

	 * @brief prints debug informations
	 *
	 * this function prints statistics data on stdout 
	 *
        */
	void dump();

        /**
	 * @brief get total lost packets
	 *
	 * this function gets total lost packets within live of RTP stream
	 *
	 * @return count of lost pakcets
        */
	u_int32_t getLost() { return s->probation ? 0 : ((s->cycles + s->max_seq) - s->base_seq + 1) - s->received; };

private: 
	/*
	* Per-source state information
	*/
	typedef struct {
		u_int16_t max_seq;		//!< highest seq. number seen 
		u_int32_t cycles;		//!< shifted count of seq. number cycles
		u_int32_t base_seq;		//!< base seq number
		u_int32_t bad_seq;		//!< last 'bad' seq number + 1
		u_int32_t probation;		//!< sequ. packets till source is valid
		u_int32_t received;		//!< packets received
		u_int32_t expected_prior;	//!< packet expected at last interval
		u_int32_t received_prior;	//!< packet received at last interval
		u_int32_t transit;		//!< relative trans time for prev pkt
		u_int32_t jitter;		//!< estimated jitter
		u_int32_t lost;			//!< lost packets
		struct timeval lastTimeRec;	//!< last received time from pcap packet header
		u_int32_t lastTimeStamp;	//!< last received timestamp from RTP header
		int delay;
		long double fdelay;
		long double prevjitter;
		double avgdelay;
	} source;

	struct pcap_pkthdr *header;
	struct timeval ts;
	source *s;
	bool first;
	int nintervals;

	struct RTPFixedHeader {
#if     __BYTE_ORDER == __BIG_ENDIAN
		// For big endian boxes
		unsigned char version:2;	// Version, currently 2
		unsigned char padding:1;	// Padding bit
		unsigned char extension:1;	// Extension bit
		unsigned char cc:4;		// CSRC count
		unsigned char marker:1;		// Marker bit
		unsigned char payload:7;	// Payload type
#else
		// For little endian boxes
		unsigned char cc:4;		// CSRC count
		unsigned char extension:1;	// Extension bit
		unsigned char padding:1;	// Padding bit
		unsigned char version:2;	// Version, currently 2
		unsigned char payload:7;	// Payload type
		unsigned char marker:1;		// Marker bit
#endif
		u_int16_t sequence;	// sequence number
		u_int32_t timestamp;	// timestamp
		u_int32_t sources[1];	// contributing sources
	};
       
	
	inline RTPFixedHeader* getHeader() const { return reinterpret_cast<RTPFixedHeader*>(data); }
	
	void update_stats();

	void init_seq(u_int16_t seq);
	int update_seq(u_int16_t seq);
};
#endif
