/* Martin Vit support@voipmonitor.org
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2.
*/

/* 
   
This unit implements class RTP which processes RTP packets and make statistics on them. 
Each Call class contains two RTP classes. 

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>

#include <pcap.h>

#include "rtp.h"
#include "codecs.h"
#include "jitterbuffer/asterisk/channel.h"
#include "jitterbuffer/asterisk/frame.h"
#include "jitterbuffer/asterisk/abstract_jb.h"
#include "jitterbuffer/asterisk/strings.h"

extern int verbosity;
extern int opt_saveRAW;                //save RTP payload RAW data?
extern int opt_saveWAV;                //save RTP payload RAW data?
extern int opt_saveGRAPH;	//save GRAPH data?
extern int opt_gzipGRAPH;	//save gzip GRAPH data?

using namespace std;

/* Convert timeval structure into microsecond representation */
inline u_int32_t timeval2micro(const timeval t) {
	return ((t.tv_sec * 1000000ul) + t.tv_usec); 
}

/* Subtract the `struct timeval' values X and Y,
   storing the result in RESULT.
   Return 1 if the difference is negative, otherwise 0.  */

int
timeval_subtract (struct timeval *result, struct timeval x, struct timeval y) {
	/* Perform the carry for the later subtraction by updating y. */
	if (x.tv_usec < y.tv_usec) {
		int nsec = (y.tv_usec - x.tv_usec) / 1000000 + 1;
		y.tv_usec -= 1000000 * nsec;
		y.tv_sec += nsec;
	}
	if (x.tv_usec - y.tv_usec > 1000000) {
		int nsec = (x.tv_usec - y.tv_usec) / 1000000;
		y.tv_usec += 1000000 * nsec;
		y.tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	tv_usec is certainly p60itive. */
	result->tv_sec = x.tv_sec - y.tv_sec;
	result->tv_usec = x.tv_usec - y.tv_usec;

	/* Return 1 if result is negative. */
	return x.tv_sec < y.tv_sec;
}



/* constructor */
RTP::RTP() {
	first = true;
	s = new source;
	memset(s, 0, sizeof(source));
	memset(&stats, 0, sizeof(stats));
	nintervals = 1;
	saddr = 0;
	ssrc = 0;
	gfilename[0] = '\0';
	gfileRAW = NULL;

	channel_fix1 = (ast_channel*)calloc(1, sizeof(*channel_fix1));
	channel_fix1->jitter_impl = 0; // fixed
	channel_fix1->jitter_max = 50; 
	channel_fix1->jitter_resync_threshold = 50;
	channel_fix1->last_datalen = 0;
	channel_fix1->lastbuflen = 0;

	channel_fix2 = (ast_channel*)calloc(1, sizeof(*channel_fix2));
	channel_fix2->jitter_impl = 0; // fixed
	channel_fix2->jitter_max = 200; 
	channel_fix2->jitter_resync_threshold = 200; 
	channel_fix2->last_datalen = 0;
	channel_fix2->lastbuflen = 0;

	channel_adapt = (ast_channel*)calloc(1, sizeof(*channel_adapt));
	channel_adapt->jitter_impl = 1; // adaptive
	channel_adapt->jitter_max = 500; 
	channel_adapt->jitter_resync_threshold = 500; 
	channel_adapt->last_datalen = 0;
	channel_adapt->lastbuflen = 0;

	//channel->name = "SIP/fixed";
	frame = (ast_frame*)calloc(1, sizeof(*frame));
	frame->frametype = AST_FRAME_VOICE;
	lastframetype = AST_FRAME_VOICE;
	//frame->src = "DUMMY";
	last_seq = 0;
	packetization = 0;
	last_packetization = 0;
	packetization_iterator = 0;
	payload = 0;
	codec = -1;
	prev_codec = -1;
}

/* destructor */
RTP::~RTP() {
	/*
	if(packetization)
		RTP::dump();
	*/
	delete s;
	ast_jb_destroy(channel_fix1);
	ast_jb_destroy(channel_fix2);
	ast_jb_destroy(channel_adapt);
	free(channel_fix1);
	free(channel_fix2);
	free(channel_adapt);
	free(frame);
}

#if 1
/* simulate jitterbuffer */
void
RTP::jitterbuffer(struct ast_channel *channel, int savePayload) {
	struct timeval tsdiff;	
	frame->ts = getTimestamp() / 8;
	frame->len = packetization;
	frame->marker = getMarker();
	frame->seqno = getSeqNum();
	channel->codec = codec;
	memcpy(&frame->delivery, &header->ts, sizeof(struct timeval));

       if(savePayload) {
	       frame->data = payload_data;
	       frame->datalen = payload_len;
	       channel->rawstream = gfileRAW;
	       //printf("[%p]\n", channel->rawstream);
	       if(payload_len) {
		       channel->last_datalen = payload_len;
	       }
       } else {
	       channel->rawstream = NULL;
       }

	// create jitter buffer structures 
	ast_jb_do_usecheck(channel, &header->ts);
	
	if(!channel->jb_reseted) {
		// initializing jitterbuffer 
		ast_jb_empty_and_reset(channel);
		channel->jb_reseted = 1;
		memcpy(&channel->last_ts, &header->ts, sizeof(struct timeval));
		ast_jb_put(channel, frame, &header->ts);
		return;
	}

	/* calculate time difference between last pakcet and current packet + packetization time*/ 
	int msdiff = ast_tvdiff_ms( header->ts, ast_tvadd(channel->last_ts, ast_samp2tv(packetization, 1000)) );
	//printf("ms:%d\n", msdiff);
	if(msdiff > packetization * 1000) {
		// difference is too big, reseting last_ts to current packet. If we dont check this it could happen to run while cycle endlessly
		memcpy(&channel->last_ts, &header->ts, sizeof(struct timeval));
		ast_jb_put(channel, frame, &header->ts);
		if(verbosity > 4) syslog(LOG_ERR, "big timestamp jump (msdiff:%d packetization: %d) in this file: %s\n", msdiff, packetization, gfilename);
		return;
	}

	/* between last packet and current packet is big timestamp difference and it could count 
	 * interpolated framed although it was silence so calculate real number of packets based 
	 * on timestamps in packet header, timestamps in rtp header and sequence numbers between 
	 * last packet and current packet
	 */

	// relative time difference calculated from packet sequence 
	u_int32_t sequencems = (frame->seqno - last_seq) * packetization;

	/* difference (in ms) between timestamps in packet header and rtp timestamps. this should 
	 * be ideally equel to zero. Negative values mean that packet arrives earlier and positive 
	 * values indicates that packet was late 
	 */
	long double transit = (timeval_subtract(&tsdiff, header->ts, s->lastTimeRec) ? -timeval2micro(tsdiff)/1000.0 : timeval2micro(tsdiff)/1000.0) - (double)(getTimestamp() - s->lastTimeStamp)/8.0;
	
	/* and now if there is bigger (lets say one second) timestamp difference (calculated from pakcet headers) 
	 * between two last packets and transit time is equel or smaller than sequencems (with 200ms toleration), 
	 * it was silence and manually mark the frame which indicates to not count interpolated frame and resynchronize jitterbuffer
	 */
	if( msdiff > 1000 and (transit <= (sequencems + 200)) ) {
		if(verbosity > 4) printf("jitterbuffer: manually marking packet, msdiff(%d) > 1000 and transit (%Lf) <= ((sequencems(%u) + 200)\n", msdiff, transit, sequencems);
		frame->marker = 1;
	}
	
	// fetch pakcet from jitterbuffer every 20 ms regardless on packet loss or delay
	while( msdiff >= packetization )  {
		if(frame->marker or lastframetype == AST_FRAME_DTMF) {
			/* if last frame was marked or DTMF, ignore interpolated frames */
			channel->last_loss_burst = 0;
		}
		ast_jb_get_and_deliver(channel, &channel->last_ts);
		/* adding packetization time to last_ts time */ // XXX: we are using temporary ast_tvadd pointer for coyping (compiler is warning about this, but I dont see problem. Make it better if you want)
		memcpy(&channel->last_ts, &ast_tvadd(channel->last_ts, ast_samp2tv(packetization, 1000)), sizeof(struct timeval));
		msdiff -= packetization;
	}

	ast_jb_put(channel, frame, &header->ts);
}
#endif

/* simulate jitterbuffer */
#if 0
void
RTP::jitterbuffer(struct ast_channel *channel) {
        frame->ts = getTimestamp() / 8;
        frame->len = packetization;
        memcpy(&frame->delivery, &header->ts, sizeof(struct timeval));

        ast_jb_do_usecheck(channel, &header->ts);

        if(!channel->jb_reseted) {
                ast_jb_empty_and_reset(channel);
                channel->jb_reseted = 1;
                memcpy(&channel->last_ts, &header->ts, sizeof(struct timeval));
                ast_jb_put(channel, frame, &header->ts);
        }

        // tohle se musi spustit kazdych 20 ms. Jelikoz je RTP::read funkce spustena az s prichozim paketem, mezi kterymi je zposdeni napr. 200ms nebo naopak mezi nimi je rozdil 1ms, musime si to osetrit
        while( (timeval2micro(channel->last_ts) + packetization * 1000) < timeval2micro(header->ts) ) {
                ast_jb_get_and_deliver(channel, &channel->last_ts);
                /* adding packetization time to last_ts time */
                // XXX: we are using temporary ast_tvadd pointer for coyping (compiler is warning about this, but it is ok. or make it better if you want)
                memcpy(&channel->last_ts, &ast_tvadd(channel->last_ts, ast_samp2tv(packetization, 1000)), sizeof(struct timeval));
        }

        ast_jb_put(channel, frame, &header->ts);
}
#endif

/* read rtp packet */
void
RTP::read(unsigned char* data, size_t len, struct pcap_pkthdr *header,  u_int32_t saddr, int seeninviteok) {

	this->data = data; 
	this->len = len;
	this->header = header;
	this->saddr =  saddr;

	u_int16_t seq = getSeqNum();
	int curpayload = getPayload();

	/* find out codec */
	if(codec == -1) {
		if(curpayload >= 96 && curpayload <= 127) {
			// for dynamic payload we look into rtpmap
			for(int i = 0; i < MAX_RTPMAP && rtpmap[i] != 0 ; i++) {
				if(curpayload == rtpmap[i] / 1000) {
					codec = rtpmap[i] - curpayload * 1000;
				}
			}
		}
	}

       /* get RTP payload header and datalen */
       if(opt_saveRAW || opt_saveWAV) {
	       payload_data = data + sizeof(RTPFixedHeader);
	       payload_len = len - sizeof(RTPFixedHeader);
	       if(getPadding()) {
		       /*
			* If set, this packet contains one or more additional padding
			* bytes at the end which are not part of the payload. The last
			* byte of the padding contains a count of how many padding bytes
			* should be ignored. Padding may be needed by some encryption
			* algorithms with fixed block sizes or for carrying several RTP
			* packets in a lower-layer protocol data unit.
			*/
		       payload_len -= ((u_int8_t *)data)[payload_len - 1];
	       }
	       if(getCC() > 0) {
		       /*
			* The number of CSRC identifiers that follow the fixed header.
			*/
		       payload_data += 4 * getCC();
		       payload_len -= 4 * getCC();
	       }
	       if(getExtension()) {
		       /*
			* If set, the fixed header is followed by exactly one header extension.
			*/
		       extension_hdr_t *rtpext;
		       if (payload_len < 4)
			       payload_len = 0;

		       // the extension, if present, is after the CSRC list.
		       rtpext = (extension_hdr_t *)((u_int8_t *)payload_data);
		       payload_data += sizeof(extension_hdr_t) + rtpext->length;
		       payload_len -= sizeof(extension_hdr_t) + rtpext->length;
	       }
	       /*
		* this is not VAD friendly

	       if(gfileRAW.is_open()) {
		       //gfileRAW.write((const char*)payload_data, payload_len);
	       }
	       */
       }



	if(!payload) {
		/* save payload to statistics based on first payload. TODO: what if payload is dynamically changing? */
		payload = curpayload;
	}

	if(curpayload == 101) {
		frame->frametype = AST_FRAME_DTMF;
	} else {
		frame->frametype = AST_FRAME_VOICE;
	}

	if(seeninviteok) {
		if(packetization_iterator < 5) {
			/* until we dont know packetization length, do not activate jitter buffer simulators
			 * also switch to jitterbuffuer only if 5 consecutive packets have the same packetization
			 */
			if(codec == PAYLOAD_ILBC || codec == PAYLOAD_G723) {
				packetization = 30;
				channel_fix1->packetization = channel_fix2->packetization = channel_adapt->packetization = packetization;
				//printf("packetization: %d\n", packetization);
				jitterbuffer(channel_fix1, 0);
				jitterbuffer(channel_fix2, opt_saveRAW || opt_saveWAV);
				jitterbuffer(channel_adapt, 0);
				packetization_iterator = 6;
			} else {
				if(seq == (last_seq + 1)) {
					// sequence numbers are ok, we can calculate packetization
					packetization = (getTimestamp() - s->lastTimeStamp) / 8;
					if(last_packetization == packetization and packetization > 0) {
						packetization_iterator++;
					} else {
						packetization_iterator = 0;
					}
					last_packetization = packetization;
				}

				if(packetization_iterator >= 5) {
					channel_fix1->packetization = channel_fix2->packetization = channel_adapt->packetization = (getTimestamp() - s->lastTimeStamp) / 8;
					//printf("packetization: %d\n", packetization);
					jitterbuffer(channel_fix1, 0);
					jitterbuffer(channel_fix2, opt_saveRAW || opt_saveWAV);
					jitterbuffer(channel_adapt, 0);
				}
			}
		} else {
			jitterbuffer(channel_fix1, 0);
			jitterbuffer(channel_fix2, opt_saveRAW || opt_saveWAV);
			jitterbuffer(channel_adapt, 0);
		}
	}

	last_seq = seq;

	if(first) {
		first = false;
		init_seq(seq);
		s->max_seq = seq - 1;
		s->probation = MIN_SEQUENTIAL;
		s->lastTimeRec = header->ts;
		s->lastTimeStamp = getTimestamp();
	} else {
		if(update_seq(seq)) {
			update_stats();
		}
	}
	lastframetype = frame->frametype;
}

/* fill internal structures by the input RTP packet */
void
RTP::fill(unsigned char* data, size_t len, struct pcap_pkthdr *header,  u_int32_t saddr) {
	this->data = data; 
	this->len = len;
	this->header = header;
	this->saddr = saddr;
}

/* update statistics data */
void
RTP::update_stats() {
	
	int lost = int((s->cycles + s->max_seq - (s->base_seq + 1)) - s->received);
	int adelay = 0;
	struct timeval tsdiff;	
	double tsdiff2;

	/* if payload == 101 (EVENT) dont make delayes on this because it confuses stats */
	if(getPayload() == 101)
		return;

	/* differences between last timestamp and current timestamp (timestamp from ip heade)
	 * frame1.time - frame0.time */
	tsdiff2 = timeval_subtract(&tsdiff, header->ts, s->lastTimeRec) ? -timeval2micro(tsdiff)/1000.0 : timeval2micro(tsdiff)/1000.0;

	long double transit = tsdiff2 - (double)(getTimestamp() - s->lastTimeStamp)/8.0;
	
	if(abs((int)transit) > 5000) {
		/* timestamp skew, discard delay, it is possible that timestamp changed  */
		s->fdelay = s->avgdelay;
		//s->fdelay = 0;
		transit = 0;
	} else {
		adelay = abs(int(transit));
		s->fdelay += transit;
	}

	/* Jitterbuffer calculation
	 * J(1) = J(0) + (|D(0,1)| - J(0))/16 */
	if(transit < 0) transit = -transit;
	long double jitter = s->prevjitter + (transit - s->prevjitter)/16. ;

	s->avgdelay = ((s->avgdelay * (long double)(s->received) - 1) + transit ) / (double)s->received;
	stats.avgjitter = ((stats.avgjitter * ( stats.received - 1 )  + jitter )) / (double)s->received;
	if(stats.maxjitter < jitter) stats.maxjitter = jitter;
	s->lastTimeRec = header->ts;
	s->lastTimeStamp = getTimestamp();
	
	if((lost > stats.last_lost) > 0) {
		stats.lost += lost - stats.last_lost;
		if((lost - stats.last_lost) < 10)
			stats.slost[lost - stats.last_lost]++;
		else 
			stats.slost[10]++;

		if(opt_saveGRAPH) {
			nintervals += lost - stats.last_lost;
			while(nintervals > 20) {
				if(opt_gzipGRAPH) {
					// compressed
					if(gfileGZ.is_open()) {
						gfile << endl;
					}
				} else {
					// uncompressed
					if(gfile.is_open()) {
						gfile << endl;
					}
				}
				nintervals -= 20;
			}
		}
	} else {
		if(opt_saveGRAPH) {
			if(opt_gzipGRAPH && gfileGZ.is_open()) {
				// compressed
				if(nintervals > 20) {
					/* after 20 packets, send new line */
					gfileGZ << endl;
					nintervals -= 20;
				}
				//gfile << s->fdelay << ":" << transit << ";";
				gfileGZ << s->fdelay << ":" << jitter << ";";
				nintervals++;
			} else if(gfile.is_open()) {
				// uncompressed
				if(nintervals > 20) {
					/* after 20 packets, send new line */
					gfile << endl;
					nintervals -= 20;
				}
				//gfile << s->fdelay << ":" << transit << ";";
				gfile << s->fdelay << ":" << jitter << ";";
				nintervals++;
			}
		}
	}
	stats.last_lost = lost;

	/* delay statistics */
	if(adelay >= 50 && adelay < 70) {
		stats.d50++;
	} else if (adelay >= 70 && adelay < 90) {
		stats.d70++;
	} else if (adelay >= 90 && adelay < 120) {
		stats.d90++;
	} else if (adelay >= 120 && adelay < 150) {
		stats.d120++;
	} else if (adelay >= 150 && adelay < 200) {
		stats.d150++;
	} else if (adelay >= 200 && adelay < 300) {
		stats.d200++;
	} else if (adelay >= 300) {
		stats.d300++;
	}
}

void
RTP::init_seq(u_int16_t seq) {
	s->base_seq = seq;
	s->max_seq = seq;
	s->bad_seq = RTP_SEQ_MOD + 1;   /* so seq == bad_seq is false */
	s->cycles = 0;
	s->received = 0;
	s->received_prior = 0;
	s->expected_prior = 0;
	s->delay = 0;
	s->fdelay = 0;
	s->prevjitter = 0;
}

/* this function is borrowed from the http://www.ietf.org/rfc/rfc3550.txt */
int
RTP::update_seq(u_int16_t seq) {
	u_int16_t udelta = seq - s->max_seq;
	/*
	* Source is not valid until MIN_SEQUENTIAL packets with
	* sequential sequence numbers have been received.
	*/
	if (s->probation) {
		/* packet is in sequence */
		if (seq == s->max_seq + 1) {
			s->probation--;
			s->max_seq = seq;
			if (s->probation == 0) {
				init_seq(seq);
				s->received++;
				stats.received++;
				return 1;
			}
		} else {
			s->probation = MIN_SEQUENTIAL - 1;
			s->max_seq = seq;
		}
		return 0;
	} else if (udelta < MAX_DROPOUT) {
		/* in order, with permissible gap */
		if (seq < s->max_seq) {
			/*
			* Sequence number wrapped - count another 64K cycle.
			*/
			s->cycles += RTP_SEQ_MOD;
		}
		s->max_seq = seq;
	} else if (udelta <= RTP_SEQ_MOD - MAX_MISORDER) {
		/* the sequence number made a very large jump */
		if (seq == s->bad_seq) {
			/*
			* Two sequential packets -- assume that the other side
			* restarted without telling us so just re-sync
			* (i.e., pretend this was the first packet).
			*/
			init_seq(seq);
		} else {
			s->bad_seq = (seq + 1) & (RTP_SEQ_MOD-1);
			return 0;
		}
	} else {
		 /* duplicate or reordered packet */
	}
	stats.received++;
	s->received++;
	return 1;
}	

void burstr_calculate(struct ast_channel *chan, u_int32_t received, double *burstr, double *lossr) {
	int lost = 0;
	int bursts = 0;
	for(int i = 0; i < 500; i++) {
		lost += i * chan->loss[i];
		bursts += chan->loss[i];
		if(verbosity > 4 and chan->loss[i] > 0) printf("loss[%d]: %d\t", i, chan->loss[i]);
	}
	if(verbosity > 4) printf("\n");
	if(received > 0 && bursts > 0) {
		*burstr = (double)((double)lost / (double)bursts) / (double)(1.0 / ( 1.0 - (double)lost / (double)received ));
		if(*burstr < 0) {
			*burstr = - *burstr;
		}
	} else {
		*burstr = 0;
	}
	//printf("total loss: %d\n", lost);
	if(received > 0) {
		*lossr = (double)((double)lost / (double)received);
	} else {
		*lossr = 0;
	}
}

/* for debug purpose */
void
RTP::dump() {
	int i;
	printf("SSRC:%u\n", ssrc);
	printf("payload:%d\n", payload);
	printf("src ip:%u\n", saddr);
	printf("Packetization:%u\n", packetization);
	printf("s->received: %d\n", s->received);
	printf("total loss:%u\n", stats.lost);
	printf("loss ratio:%f\n", (double)stats.lost / (double)s->received);
	printf("serial loss: ");
	for(i = 1; i < 11; i++) 
		printf("%d:%u ", i, stats.slost[i]);
	printf("\n");
	printf("d50: %d, d70: %d, d90: %d, d120: %d, d150: %d, d200: %d, d300: %d\n",
		stats.d50, stats.d70, stats.d90, stats.d120, stats.d150, stats.d200, stats.d300);

	double burstr, lossr;
	printf("jitter stats:\n");
	burstr_calculate(channel_fix1, s->received, &burstr, &lossr);
	//printf("s->received: %d, loss: %d, bursts: %d\n", s->received, lost, bursts);
	printf("fix(50/50)\tloss rate:\t%f\n", lossr);
	printf("fix(50/50)\tburst rate:\t%f\n", burstr);

	burstr_calculate(channel_fix2, s->received, &burstr, &lossr);
	//printf("s->received: %d, loss: %d, bursts: %d\n", s->received, lost, bursts);
	printf("fix(200/200)\tloss rate:\t%f\n", lossr);
	printf("fix(200/200)\tburst rate:\t%f\n", burstr);

	burstr_calculate(channel_adapt, s->received, &burstr, &lossr);
	//printf("s->received: %d, loss: %d, bursts: %d\n", s->received, lost, bursts);
	printf("adapt(500/500)\tloss rate:\t%f\n", lossr);
	printf("adapt(500/500)\tburst rate:\t%f\n", burstr);
	printf("---\n");
}
