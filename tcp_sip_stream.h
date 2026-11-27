#ifndef TCP_SIP_STREAM_H
#define TCP_SIP_STREAM_H

#include <stddef.h>
#include <sys/time.h>
#include <vector>

#include "tcpreassembly.h"
#include "sync_modern.h"

class SipTcpData;

/*
 * Sharded RFC-793 per-direction TCP stream reassembly engine for SIP / SIP-over-WebSocket.
 *
 * Design highlights:
 *  - 256 cache-line-padded shards with per-shard spinlocks (zero global lock contention).
 *  - Canonical bidirectional 4-tuple key -> 1 hash probe per packet, O(1) chained hash table
 *    (C++98 native, GCC 4.4.5 / 32-bit i686 safe), O(1) intrusive LRU eviction.
 *  - Two independent RFC-793 byte-stream reassemblers per TCP connection (one per direction)
 *    with exact modular 32-bit sequence arithmetic (handles wraparound and seq == 0).
 *  - Zero-copy fast path for single-segment in-order SIP messages (dispatched directly from
 *    caller packet buffer after releasing the shard lock).
 *  - O(1) retransmission/duplicate suppression via rcv_nxt (eliminates per-message MD5).
 *  - Gap recovery + stream resync after capture drops or zeroed segments, plus cold-path
 *    pre-first_seq reassembly for parallel worker startup ordering on mid-stream wild links.
 */
class TcpSipStreamEngine {
public:
	static const unsigned NUM_SHARDS = 256;
	static const u_int32_t MAX_BUF_BYTES = 512u * 1024u;
	static const u_int32_t MAX_SIP_MSG_BYTES = 1024u * 1024u;
	static const u_int32_t MAX_WS_FRAME_BYTES = 512u * 1024u;
	static const u_int32_t MAX_OOO_SEGS = 128u;
	static const u_int32_t MAX_OOO_BYTES = 512u * 1024u;
	static const u_int32_t GAP_ADVANCE_SEGS = 96u;
	static const u_int32_t GAP_ADVANCE_BYTES = 256u * 1024u;
	static const u_int64_t GAP_ADVANCE_MS = 500ULL;
	static const u_int32_t MAX_OOO_WINDOW = 2u * 1024u * 1024u;
	static const u_int32_t PRE_WINDOW_BYTES = 512u * 1024u;
	static const u_int32_t PRE_TAIL_MAX_BYTES = 64u * 1024u;
	static const u_int64_t PRE_WINDOW_MS = 2000ULL;

	struct OutMsg {
		const u_char *ptr;
		u_int32_t len;
		u_int32_t seq;
		u_int32_t ack;
		timeval ts;
		bool owned;
	};

	struct OutBatch {
		static const unsigned INLINE_CAP = 8;
		OutMsg inline_msgs[INLINE_CAP];
		unsigned inline_count;
		std::vector<OutMsg> overflow;

		OutBatch() : inline_count(0) {}
		~OutBatch() {
			releaseOwned();
		}
		inline void push(const OutMsg &m) {
			if(inline_count < INLINE_CAP) {
				inline_msgs[inline_count++] = m;
			} else {
				overflow.push_back(m);
			}
		}
		inline unsigned size() const {
			return inline_count + (unsigned)overflow.size();
		}
		inline const OutMsg &at(unsigned i) const {
			return i < inline_count ? inline_msgs[i] : overflow[i - inline_count];
		}
		inline void releaseOwned() {
			for(unsigned i = 0; i < inline_count; ++i) {
				if(inline_msgs[i].owned && inline_msgs[i].ptr) {
					delete [] const_cast<u_char*>(inline_msgs[i].ptr);
					inline_msgs[i].ptr = NULL;
				}
			}
			for(size_t i = 0; i < overflow.size(); ++i) {
				if(overflow[i].owned && overflow[i].ptr) {
					delete [] const_cast<u_char*>(overflow[i].ptr);
					overflow[i].ptr = NULL;
				}
			}
			inline_count = 0;
			overflow.clear();
		}
	};

	struct OooSeg {
		OooSeg *next;
		u_int32_t seq;
		u_int32_t ack;
		u_int32_t len;
		timeval ts;
		u_char data[1];
	};

	struct DirStream {
		bool seq_init;
		bool saw_syn;
		bool synced;
		bool has_seq_bound;
		bool hdr_has_cl;
		u_int32_t first_seq;
		u_int32_t rcv_nxt;
		u_int32_t max_seq_bound;
		u_int32_t buf_seq;
		u_char *buf;
		u_int32_t buf_cap;
		u_int32_t buf_head;
		u_int32_t buf_tail;
		int hdr_scan_off;
		u_int32_t hdr_cl;
		int hdr_total_len;
		timeval msg_ts;
		u_int32_t msg_ack;
		OooSeg *ooo_head;
		u_int32_t ooo_count;
		u_int32_t ooo_bytes;
		u_int64_t ooo_first_ms;
		u_int64_t created_ms;
		DirStream *pre;
		u_char *pre_tail;
		u_int32_t pre_tail_len;
		u_int32_t pre_tail_seq;

		DirStream();
		~DirStream();

		void reset();
		void clearBuffer();
		void clearOoo();
		void clearPre();
		inline u_int32_t bufLen() const {
			return buf_tail - buf_head;
		}
		void bufAppend(const u_char *data, u_int32_t len, u_int32_t caplen,
			       u_int32_t seg_seq, timeval ts, u_int32_t ack);
		void bufPrepend(const u_char *data, u_int32_t len, u_int32_t caplen,
				u_int32_t seg_seq, timeval ts, u_int32_t ack);
		void insertOoo(u_int32_t seq, u_int32_t ack, timeval ts,
			       const u_char *data, u_int32_t len, u_int32_t caplen,
			       u_int64_t pkt_ms);
		void drainOoo();
		bool advanceGap(OutBatch &out);
		void flushAll(OutBatch &out);

		template<bool CopyOut>
		u_int32_t frameBuffer(const u_char *data, u_int32_t len, u_int32_t base_seq,
				      timeval ts, u_int32_t ack, OutBatch &out,
				      bool &had_header_state);

		void pushSegment(u_int32_t seq, u_int32_t ack, u_int8_t tcp_flags,
				 timeval ts, u_int64_t pkt_ms,
				 const u_char *data, u_int32_t datalen, u_int32_t datacaplen,
				 OutBatch &out);

	private:
		void pushPreFirstSeq(u_int32_t seq, u_int32_t ack, u_int8_t tcp_flags,
				     timeval ts, u_int64_t pkt_ms,
				     const u_char *data, u_int32_t datalen, u_int32_t datacaplen,
				     OutBatch &out) __attribute__((noinline, cold));
		void savePreTail(const u_char *data, u_int32_t len, u_int32_t seq) __attribute__((noinline, cold));
		void maybeRetirePre(u_int64_t pkt_ms, OutBatch &out) __attribute__((noinline, cold));
	};

	struct LinkKey {
		vmIP ip_lo;
		vmIP ip_hi;
		u_int16_t port_lo;
		u_int16_t port_hi;

		inline bool operator == (const LinkKey &o) const {
			return port_lo == o.port_lo &&
			       port_hi == o.port_hi &&
			       ip_lo == o.ip_lo &&
			       ip_hi == o.ip_hi;
		}
	};

	struct Link {
		LinkKey key;
		u_int64_t hash;
		Link *hash_next;
		Link *lru_prev;
		Link *lru_next;
		u_int64_t last_time_ms;
		DirStream dirs[2];
		u_char eth_header[50];
		u_int32_t eth_header_len;
		u_int16_t handle_index;
		int dlt;
		int sensor_id;
		vmIP sensor_ip;
		sPacketInfoData pid;
		bool skip_ws_inflate_timeout;

		Link(const LinkKey &k, u_int64_t h)
			: key(k), hash(h), hash_next(NULL), lru_prev(NULL), lru_next(NULL),
			  last_time_ms(0), eth_header_len(0), handle_index(0),
			  dlt(0), sensor_id(0), skip_ws_inflate_timeout(false) {
			pid.clear();
		}
	};

	struct Shard {
		cPaddedSpinLock lock;
		Link **buckets;
		u_int32_t bucket_mask;
		u_int32_t link_count;
		Link *lru_head;
		Link *lru_tail;
		u_int64_t act_time_ms;
		u_int64_t last_cleanup_ms;
		char _pad[64];

		Shard()
			: buckets(NULL), bucket_mask(0), link_count(0),
			  lru_head(NULL), lru_tail(NULL), act_time_ms(0), last_cleanup_ms(0) {
			lock.init();
		}
		~Shard();

		void ensureBuckets();
		void rehash();
		Link *find(const LinkKey &key, u_int64_t hash);
		void insert(Link *link);
		void unlink(Link *link);
		void touchLru(Link *link);
	};

public:
	explicit TcpSipStreamEngine(TcpReassembly *owner);
	~TcpSipStreamEngine();

	void push(pcap_pkthdr *header, iphdr2 *header_ip, u_char *packet,
		  u_int16_t handle_index, int dlt, int sensor_id, vmIP sensor_ip, sPacketInfoData pid,
		  void *uData, void *uData2);
	void cleanup(bool all);
	void getStats(u_int32_t &links, u_int32_t &buffered_dirs, u_int32_t &ooo_segs) const;
	size_t getLinkCount() const;

	static int classifySipStart(const u_char *p, u_int32_t len);
	static int findNextSipStart(const u_char *p, u_int32_t len);
	static u_int64_t hashLinkKey(const LinkKey &k);
	static inline void makeCanonicalKey(const vmIP &saddr, u_int16_t sport,
					    const vmIP &daddr, u_int16_t dport,
					    LinkKey &out_key, int &out_dir) {
		int cmp = saddr.compare(daddr);
		if(cmp < 0 || (cmp == 0 && sport <= dport)) {
			out_key.ip_lo = saddr;
			out_key.ip_hi = daddr;
			out_key.port_lo = sport;
			out_key.port_hi = dport;
			out_dir = 0;
		} else {
			out_key.ip_lo = daddr;
			out_key.ip_hi = saddr;
			out_key.port_lo = dport;
			out_key.port_hi = sport;
			out_dir = 1;
		}
	}

private:
	struct FlushMeta {
		vmIP ip_src;
		vmIP ip_dst;
		vmPort port_src;
		vmPort port_dst;
		u_char eth_header[50];
		u_int32_t eth_header_len;
		u_int16_t handle_index;
		int dlt;
		int sensor_id;
		vmIP sensor_ip;
		sPacketInfoData pid;
		OutBatch batch;
	};

	void evictExpiredLocked(Shard &sh, u_int64_t now_ms, u_int64_t timeout_ms,
				bool all, std::vector<FlushMeta*> *flushed);
	void dispatchFlushed(std::vector<FlushMeta*> &flushed, void *uData, void *uData2);

	TcpReassembly *owner;
	Shard shards[NUM_SHARDS];
	volatile u_int32_t stat_links;
};

#endif // TCP_SIP_STREAM_H
