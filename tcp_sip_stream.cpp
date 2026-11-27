#include "tcp_sip_stream.h"
#include "sip_tcp_data.h"
#include "sniff_proc_class.h"
#include "sniff_inline.h"
#include "websocket.h"

#include <string.h>

extern bool opt_sip_tcp_reassembly_ext;


// --- SIP start-line classifier & resync scanner ---

static inline int checkTokenOrPrefix(const u_char *p, u_int32_t len, const char *tok, u_int32_t tok_len) {
	u_int32_t n = len < tok_len ? len : tok_len;
	if(memcmp(p, tok, n) != 0) {
		return -1;
	}
	return len >= tok_len ? 1 : 0;
}

int TcpSipStreamEngine::classifySipStart(const u_char *p, u_int32_t len) {
	if(!p || !len) {
		return 0;
	}
	switch(p[0]) {
	case 'I': {
		int r1 = checkTokenOrPrefix(p, len, "INVITE ", 7);
		if(r1 >= 0) return r1;
		return checkTokenOrPrefix(p, len, "INFO ", 5);
	}
	case 'S': {
		if(len == 1) return 0;
		if(p[1] == 'I') {
			int r = checkTokenOrPrefix(p, len, "SIP/2.0 ", 8);
			if(r <= 0) return r;
			if(len < 11) return 0;
			if(p[8] >= '1' && p[8] <= '6' &&
			   p[9] >= '0' && p[9] <= '9' &&
			   p[10] >= '0' && p[10] <= '9') {
				return 1;
			}
			return -1;
		}
		return checkTokenOrPrefix(p, len, "SUBSCRIBE ", 10);
	}
	case 'A':
		return checkTokenOrPrefix(p, len, "ACK ", 4);
	case 'B':
		return checkTokenOrPrefix(p, len, "BYE ", 4);
	case 'C':
		return checkTokenOrPrefix(p, len, "CANCEL ", 7);
	case 'O':
		return checkTokenOrPrefix(p, len, "OPTIONS ", 8);
	case 'R': {
		int r1 = checkTokenOrPrefix(p, len, "REGISTER ", 9);
		if(r1 >= 0) return r1;
		return checkTokenOrPrefix(p, len, "REFER ", 6);
	}
	case 'P': {
		int r1 = checkTokenOrPrefix(p, len, "PRACK ", 6);
		if(r1 >= 0) return r1;
		return checkTokenOrPrefix(p, len, "PUBLISH ", 8);
	}
	case 'U':
		return checkTokenOrPrefix(p, len, "UPDATE ", 7);
	case 'N':
		return checkTokenOrPrefix(p, len, "NOTIFY ", 7);
	case 'M':
		return checkTokenOrPrefix(p, len, "MESSAGE ", 8);
	default:
		return -1;
	}
}

static inline bool isWsCandidateByte(u_char b) {
	return b == 0x81 || b == 0xC1 || (b >= 0x88 && b <= 0x8A);
}

int TcpSipStreamEngine::findNextSipStart(const u_char *p, u_int32_t len) {
	u_int32_t pos = 0;
	while(pos < len) {
		const u_char *nl = (const u_char*)memchr(p + pos, '\n', len - pos);
		const u_char *zr = (const u_char*)memchr(p + pos, '\0', nl ? (size_t)(nl - (p + pos)) : (size_t)(len - pos));
		const u_char *brk = zr ? zr : nl;
		if(!brk) {
			break;
		}
		u_int32_t cand = (u_int32_t)(brk - p) + 1;
		while(cand < len && (p[cand] == '\r' || p[cand] == '\n' || p[cand] == '\0')) {
			++cand;
		}
		if(cand >= len) {
			return -1;
		}
		if(classifySipStart(p + cand, len - cand) >= 0) {
			return (int)cand;
		}
		pos = cand;
	}
	// Fallback for non-newline-terminated bodies (e.g. XML/binary body right before INVITE/SIP/2.0)
	if(len >= 8) {
		u_int32_t scan_len = len < 8192u ? len : 8192u;
		const u_char *h1 = (const u_char*)memmem(p + 1, scan_len - 1, "INVITE ", 7);
		const u_char *h2 = (const u_char*)memmem(p + 1, scan_len - 1, "SIP/2.0 ", 8);
		const u_char *best = (h1 && h2) ? (h1 < h2 ? h1 : h2) : (h1 ? h1 : h2);
		if(best && classifySipStart(best, len - (u_int32_t)(best - p)) >= 0) {
			return (int)(best - p);
		}
	}
	return -1;
}

u_int64_t TcpSipStreamEngine::hashLinkKey(const LinkKey &k) {
	u_int64_t h = (u_int64_t)k.ip_lo.hash();
	h = ((h << 13) | (h >> 51)) ^ (u_int64_t)k.ip_hi.hash();
	h = ((h << 7) | (h >> 57)) ^ (((u_int64_t)k.port_lo << 16) | (u_int64_t)k.port_hi);
	h ^= h >> 33;
	h *= 0xff51afd7ed558ccdULL;
	h ^= h >> 33;
	h *= 0xc4ceb9fe1a85ec53ULL;
	h ^= h >> 33;
	return h;
}


// --- DirStream ---

TcpSipStreamEngine::DirStream::DirStream()
	: seq_init(false), saw_syn(false), synced(false), has_seq_bound(false), hdr_has_cl(false),
	  first_seq(0), rcv_nxt(0), max_seq_bound(0), buf_seq(0),
	  buf(NULL), buf_cap(0), buf_head(0), buf_tail(0),
	  hdr_scan_off(0), hdr_cl(0), hdr_total_len(0),
	  msg_ack(0),
	  ooo_head(NULL), ooo_count(0), ooo_bytes(0), ooo_first_ms(0),
	  created_ms(0),
	  pre(NULL), pre_tail(NULL), pre_tail_len(0), pre_tail_seq(0) {
	msg_ts.tv_sec = 0;
	msg_ts.tv_usec = 0;
}

TcpSipStreamEngine::DirStream::~DirStream() {
	clearOoo();
	clearPre();
	if(buf) {
		delete [] buf;
		buf = NULL;
	}
}

void TcpSipStreamEngine::DirStream::clearBuffer() {
	buf_head = 0;
	buf_tail = 0;
	hdr_scan_off = 0;
	hdr_has_cl = false;
	hdr_cl = 0;
	hdr_total_len = 0;
}

void TcpSipStreamEngine::DirStream::clearOoo() {
	while(ooo_head) {
		OooSeg *next = ooo_head->next;
		delete [] reinterpret_cast<u_char*>(ooo_head);
		ooo_head = next;
	}
	ooo_count = 0;
	ooo_bytes = 0;
	ooo_first_ms = 0;
}

void TcpSipStreamEngine::DirStream::clearPre() {
	if(pre) {
		delete pre;
		pre = NULL;
	}
	if(pre_tail) {
		delete [] pre_tail;
		pre_tail = NULL;
		pre_tail_len = 0;
		pre_tail_seq = 0;
	}
}

void TcpSipStreamEngine::DirStream::reset() {
	seq_init = false;
	saw_syn = false;
	synced = false;
	first_seq = 0;
	rcv_nxt = 0;
	buf_seq = 0;
	clearBuffer();
	clearOoo();
	clearPre();
	created_ms = 0;
}

void TcpSipStreamEngine::DirStream::bufAppend(const u_char *data, u_int32_t len, u_int32_t caplen,
					      u_int32_t seg_seq, timeval ts, u_int32_t ack) {
	if(!len) {
		return;
	}
	u_int32_t cur_len = bufLen();
	if(cur_len == 0) {
		buf_head = 0;
		buf_tail = 0;
		buf_seq = seg_seq;
		msg_ts = ts;
		msg_ack = ack;
		hdr_scan_off = 0;
		hdr_has_cl = false;
		hdr_cl = 0;
		hdr_total_len = 0;
	} else if(cur_len + len > MAX_BUF_BYTES) {
		// Safety cap against malformed streams without valid SIP boundaries
		clearBuffer();
		cur_len = 0;
		buf_seq = seg_seq;
		msg_ts = ts;
		msg_ack = ack;
		if(len > MAX_BUF_BYTES) {
			u_int32_t drop = len - MAX_BUF_BYTES;
			data += drop;
			seg_seq += drop;
			buf_seq = seg_seq;
			len = MAX_BUF_BYTES;
			caplen = caplen > drop ? (caplen - drop) : 0;
		}
	}
	if(buf_tail + len > buf_cap) {
		if(buf_head > 0 && cur_len + len <= buf_cap) {
			memmove(buf, buf + buf_head, cur_len);
			buf_head = 0;
			buf_tail = cur_len;
		} else {
			u_int32_t needed = cur_len + len;
			u_int32_t new_cap = buf_cap ? (buf_cap * 2) : 4096u;
			while(new_cap < needed) {
				new_cap *= 2;
			}
			if(new_cap > MAX_BUF_BYTES && needed <= MAX_BUF_BYTES) {
				new_cap = MAX_BUF_BYTES;
			}
			u_char *nb = new FILE_LINE(0) u_char[new_cap];
			if(cur_len) {
				memcpy(nb, buf + buf_head, cur_len);
			}
			delete [] buf;
			buf = nb;
			buf_cap = new_cap;
			buf_head = 0;
			buf_tail = cur_len;
		}
	}
	u_int32_t copy_len = caplen < len ? caplen : len;
	if(copy_len > 0 && data) {
		memcpy(buf + buf_tail, data, copy_len);
	}
	if(copy_len < len) {
		memset(buf + buf_tail + copy_len, ' ', len - copy_len);
	}
	buf_tail += len;
}

void TcpSipStreamEngine::DirStream::bufPrepend(const u_char *data, u_int32_t len, u_int32_t caplen,
					       u_int32_t seg_seq, timeval ts, u_int32_t ack) {
	if(!len) {
		return;
	}
	u_int32_t cur_len = bufLen();
	if(cur_len + len > MAX_BUF_BYTES) {
		return;
	}
	u_int32_t needed = cur_len + len;
	if(needed > buf_cap) {
		u_int32_t new_cap = buf_cap ? (buf_cap * 2) : 4096u;
		while(new_cap < needed) {
			new_cap *= 2;
		}
		u_char *nb = new FILE_LINE(0) u_char[new_cap];
		if(cur_len) {
			memcpy(nb + len, buf + buf_head, cur_len);
		}
		delete [] buf;
		buf = nb;
		buf_cap = new_cap;
	} else if(cur_len) {
		memmove(buf + len, buf + buf_head, cur_len);
	}
	u_int32_t copy_len = caplen < len ? caplen : len;
	if(copy_len > 0 && data) {
		memcpy(buf, data, copy_len);
	}
	if(copy_len < len) {
		memset(buf + copy_len, ' ', len - copy_len);
	}
	buf_head = 0;
	buf_tail = needed;
	buf_seq = seg_seq;
	msg_ts = ts;
	msg_ack = ack;
	hdr_scan_off = 0;
	hdr_has_cl = false;
	hdr_cl = 0;
	hdr_total_len = 0;
}

void TcpSipStreamEngine::DirStream::insertOoo(u_int32_t seq, u_int32_t ack, timeval ts,
					      const u_char *data, u_int32_t len, u_int32_t caplen,
					      u_int64_t pkt_ms) {
	if(!len || ooo_count >= MAX_OOO_SEGS || ooo_bytes + len > MAX_OOO_BYTES) {
		return;
	}
	OooSeg **pp = &ooo_head;
	while(*pp && tcp_seq_lt((*pp)->seq, seq)) {
		pp = &((*pp)->next);
	}
	if(*pp && (*pp)->seq == seq) {
		if(len <= (*pp)->len) {
			return;
		}
		// Replace shorter segment at the exact same seq with longer retransmission
		OooSeg *old = *pp;
		u_char *raw = new FILE_LINE(0) u_char[offsetof(OooSeg, data) + len];
		OooSeg *seg = reinterpret_cast<OooSeg*>(raw);
		seg->next = old->next;
		seg->seq = seq;
		seg->ack = ack;
		seg->len = len;
		seg->ts = ts;
		u_int32_t copy_len = caplen < len ? caplen : len;
		if(copy_len > 0 && data) {
			memcpy(seg->data, data, copy_len);
		}
		if(copy_len < len) {
			memset(seg->data + copy_len, ' ', len - copy_len);
		}
		ooo_bytes = ooo_bytes - old->len + len;
		*pp = seg;
		delete [] reinterpret_cast<u_char*>(old);
		return;
	}
	u_char *raw = new FILE_LINE(0) u_char[offsetof(OooSeg, data) + len];
	OooSeg *seg = reinterpret_cast<OooSeg*>(raw);
	seg->next = *pp;
	seg->seq = seq;
	seg->ack = ack;
	seg->len = len;
	seg->ts = ts;
	u_int32_t copy_len = caplen < len ? caplen : len;
	if(copy_len > 0 && data) {
		memcpy(seg->data, data, copy_len);
	}
	if(copy_len < len) {
		memset(seg->data + copy_len, ' ', len - copy_len);
	}
	*pp = seg;
	++ooo_count;
	ooo_bytes += len;
	if(ooo_count == 1) {
		ooo_first_ms = pkt_ms;
	}
}

void TcpSipStreamEngine::DirStream::drainOoo() {
	while(ooo_head && tcp_seq_le(ooo_head->seq, rcv_nxt)) {
		OooSeg *seg = ooo_head;
		ooo_head = seg->next;
		--ooo_count;
		ooo_bytes -= seg->len;
		u_int32_t trim = (u_int32_t)(rcv_nxt - seg->seq);
		if(trim < seg->len) {
			u_int32_t add_len = seg->len - trim;
			if(has_seq_bound && tcp_seq_gt(rcv_nxt + add_len, max_seq_bound)) {
				if(tcp_seq_ge(rcv_nxt, max_seq_bound)) {
					add_len = 0;
				} else {
					add_len = (u_int32_t)(max_seq_bound - rcv_nxt);
				}
			}
			if(add_len > 0) {
				bufAppend(seg->data + trim, add_len, add_len, rcv_nxt, seg->ts, seg->ack);
				rcv_nxt += add_len;
			}
		}
		delete [] reinterpret_cast<u_char*>(seg);
	}
	if(!ooo_head) {
		ooo_first_ms = 0;
	}
}

void TcpSipStreamEngine::DirStream::savePreTail(const u_char *data, u_int32_t len, u_int32_t seq) {
	if(pre_tail || !data || !len) {
		return;
	}
	u_int32_t keep = len <= PRE_TAIL_MAX_BYTES ? len : PRE_TAIL_MAX_BYTES;
	pre_tail = new FILE_LINE(0) u_char[keep];
	memcpy(pre_tail, data, keep);
	pre_tail_len = keep;
	pre_tail_seq = seq;
}

template<bool CopyOut>
u_int32_t TcpSipStreamEngine::DirStream::frameBuffer(const u_char *data, u_int32_t len, u_int32_t base_seq,
						     timeval ts, u_int32_t ack, OutBatch &out,
						     bool &had_header_state) {
	u_int32_t off = 0;
	while(off < len) {
		// Skip RFC 5626 CRLF keepalives and zeroed capture bytes between messages.
		// On an unsynced wild link, only commit the skip if a valid SIP/WS start follows,
		// so an out-of-order mid-message segment starting with '\r'/'\n' preserves all bytes
		// for Case A predecessor prepending.
		u_int32_t skip_start = off;
		u_int32_t scan = off;
		while(scan < len && (data[scan] == '\r' || data[scan] == '\n' || data[scan] == '\0')) {
			++scan;
		}
		if(scan >= len) {
			if(synced || saw_syn || has_seq_bound || len > PRE_TAIL_MAX_BYTES) {
				off = scan;
			}
			break;
		}
		if(scan > skip_start) {
			bool valid_after = isWsCandidateByte(data[scan]) || classifySipStart(data + scan, len - scan) >= 0;
			if(!valid_after && !synced && !saw_syn && !has_seq_bound && !pre && len <= PRE_TAIL_MAX_BYTES &&
			   findNextSipStart(data + scan, len - scan) < 0) {
				break;
			}
			off = scan;
			if(had_header_state) {
				hdr_scan_off = 0;
				hdr_has_cl = false;
				hdr_cl = 0;
				hdr_total_len = 0;
				had_header_state = false;
			}
		}

		const u_char *p = data + off;
		u_int32_t rem = len - off;

		// Check WebSocket frame first (FIN=1 bytes >= 0x80 never collide with ASCII SIP methods)
		if(isWsCandidateByte(p[0])) {
			cWebSocketHeader ws(const_cast<u_char*>(p), rem);
			if(!ws.isHeaderSizeOk()) {
				break;
			}
			u_int64_t flen64 = (u_int64_t)ws.getHeaderLength() + ws.getDataLength();
			if(flen64 > MAX_WS_FRAME_BYTES || flen64 < 2) {
				// Invalid WebSocket frame header -> resync past this byte
				++off;
				continue;
			}
			if((u_int64_t)rem < flen64) {
				break;
			}
			u_int32_t flen = (u_int32_t)flen64;
			if(p[0] == 0x81 || p[0] == 0xC1) {
				OutMsg msg;
				if(CopyOut) {
					u_char *copy = new FILE_LINE(0) u_char[flen];
					memcpy(copy, p, flen);
					msg.ptr = copy;
					msg.owned = true;
				} else {
					msg.ptr = p;
					msg.owned = false;
				}
				msg.len = flen;
				msg.seq = base_seq + off;
				msg.ack = ack;
				msg.ts = ts;
				out.push(msg);
			}
			synced = true;
			off += flen;
			continue;
		}

		// Check SIP start-line
		int sip_start = classifySipStart(p, rem);
		if(sip_start == 0) {
			// Valid prefix of a SIP method/status split across TCP segment boundary
			break;
		}
		if(sip_start < 0) {
			// Not a valid SIP start-line: resync to the next SIP message in stream
			int next_pos = findNextSipStart(p, rem);
			if(next_pos > 0) {
				if(!synced && !saw_syn && !has_seq_bound && !pre_tail) {
					savePreTail(p, (u_int32_t)next_pos, base_seq + off);
				}
				off += (u_int32_t)next_pos;
				if(had_header_state) {
					hdr_scan_off = 0;
					hdr_has_cl = false;
					hdr_cl = 0;
					hdr_total_len = 0;
					had_header_state = false;
				}
				continue;
			}
			// No SIP start found yet; on a brand-new unsynced wild link, retain bytes up to
			// PRE_TAIL_MAX_BYTES so an out-of-order earlier segment can prepend cleanly.
			if(!synced && !saw_syn && !has_seq_bound && !pre && rem <= PRE_TAIL_MAX_BYTES) {
				break;
			}
			// Otherwise keep up to 16 trailing bytes in case method keyword is split across segments
			if(rem > 16) {
				u_int32_t discard = rem - 16;
				if(!synced && !saw_syn && !has_seq_bound && !pre_tail) {
					savePreTail(p, discard, base_seq + off);
				}
				off += discard;
			}
			break;
		}

		// Parse SIP header & Content-Length in a single read-only pass
		bool has_cl = had_header_state ? hdr_has_cl : false;
		u_int32_t cl = had_header_state ? hdr_cl : 0;
		int hdr_tot = had_header_state ? hdr_total_len : 0;
		int scan_off = had_header_state ? hdr_scan_off : 0;

		if(hdr_tot == 0) {
			int next_scan = scan_off;
			int hr = TcpReassemblySip::parseSipHeader(p, (int)rem, has_cl, cl, hdr_tot, scan_off, &next_scan);
			if(hr == 0) {
				if(CopyOut) {
					hdr_has_cl = has_cl;
					hdr_cl = cl;
					hdr_total_len = 0;
					hdr_scan_off = next_scan;
					had_header_state = true;
				}
				break;
			}
			if(hr < 0) {
				// Corrupted header (e.g. NUL bytes from zeroed packet or > 64KB without CRLFCRLF) -> resync
				hdr_scan_off = 0;
				hdr_has_cl = false;
				hdr_cl = 0;
				hdr_total_len = 0;
				had_header_state = false;
				int next_pos = findNextSipStart(p + 1, rem - 1);
				if(next_pos > 0) {
					off += 1 + (u_int32_t)next_pos;
					continue;
				}
				off = rem > 16 ? (len - 16) : (off + 1);
				break;
			}
		}

		u_int64_t total64 = (u_int64_t)hdr_tot + (u_int64_t)cl;
		if(total64 > MAX_SIP_MSG_BYTES) {
			hdr_scan_off = 0;
			hdr_has_cl = false;
			hdr_cl = 0;
			hdr_total_len = 0;
			had_header_state = false;
			++off;
			continue;
		}
		if((u_int64_t)rem < total64) {
			if(CopyOut) {
				hdr_has_cl = has_cl;
				hdr_cl = cl;
				hdr_total_len = hdr_tot;
				hdr_scan_off = hdr_tot;
				had_header_state = true;
			}
			break;
		}

		u_int32_t msg_len = (u_int32_t)total64;
		OutMsg msg;
		if(CopyOut) {
			u_char *copy = new FILE_LINE(0) u_char[msg_len];
			memcpy(copy, p, msg_len);
			msg.ptr = copy;
			msg.owned = true;
		} else {
			msg.ptr = p;
			msg.owned = false;
		}
		msg.len = msg_len;
		msg.seq = base_seq + off;
		msg.ack = ack;
		msg.ts = ts;
		out.push(msg);

		synced = true;
		off += msg_len;
		hdr_scan_off = 0;
		hdr_has_cl = false;
		hdr_cl = 0;
		hdr_total_len = 0;
		had_header_state = false;
	}
	return off;
}

bool TcpSipStreamEngine::DirStream::advanceGap(OutBatch &out) {
	if(!ooo_head) {
		return false;
	}
	// Discard incomplete partial message interrupted by the missing gap
	clearBuffer();
	rcv_nxt = ooo_head->seq;
	drainOoo();
	if(bufLen() > 0) {
		bool had_hdr = (hdr_total_len > 0 || hdr_scan_off > 0);
		u_int32_t consumed = frameBuffer<true>(buf + buf_head, bufLen(), buf_seq, msg_ts, msg_ack, out, had_hdr);
		buf_head += consumed;
		buf_seq += consumed;
		if(buf_head == buf_tail) {
			clearBuffer();
		}
	}
	return true;
}

void TcpSipStreamEngine::DirStream::flushAll(OutBatch &out) {
	if(pre) {
		pre->flushAll(out);
		delete pre;
		pre = NULL;
	}
	if(bufLen() > 0) {
		bool had_hdr = (hdr_total_len > 0 || hdr_scan_off > 0);
		u_int32_t consumed = frameBuffer<true>(buf + buf_head, bufLen(), buf_seq, msg_ts, msg_ack, out, had_hdr);
		buf_head += consumed;
		buf_seq += consumed;
		if(buf_head == buf_tail) {
			clearBuffer();
		}
	}
	while(ooo_head) {
		advanceGap(out);
	}
	clearBuffer();
	clearOoo();
	clearPre();
}

void TcpSipStreamEngine::DirStream::maybeRetirePre(u_int64_t pkt_ms, OutBatch &out) {
	if(!pre && !pre_tail) {
		return;
	}
	bool expired = (pkt_ms > created_ms && pkt_ms - created_ms > PRE_WINDOW_MS);
	if(pre && (pre->rcv_nxt == pre->max_seq_bound || expired)) {
		// Append saved pre_tail if pre stopped right at pre_tail_seq
		if(pre_tail && pre->rcv_nxt == pre_tail_seq) {
			pre->has_seq_bound = false;
			pre->bufAppend(pre_tail, pre_tail_len, pre_tail_len, pre_tail_seq, pre->msg_ts, pre->msg_ack);
			pre->rcv_nxt += pre_tail_len;
			bool had_hdr = (pre->hdr_total_len > 0 || pre->hdr_scan_off > 0);
			u_int32_t consumed = pre->frameBuffer<true>(pre->buf + pre->buf_head, pre->bufLen(), pre->buf_seq,
								    pre->msg_ts, pre->msg_ack, out, had_hdr);
			pre->buf_head += consumed;
			pre->buf_seq += consumed;
		}
		pre->flushAll(out);
		if(tcp_seq_lt(pre->first_seq, first_seq)) {
			first_seq = pre->first_seq;
		}
		clearPre();
	} else if(!pre && pre_tail && expired) {
		delete [] pre_tail;
		pre_tail = NULL;
		pre_tail_len = 0;
		pre_tail_seq = 0;
	}
}

void TcpSipStreamEngine::DirStream::pushPreFirstSeq(u_int32_t seq, u_int32_t ack, u_int8_t tcp_flags,
						    timeval ts, u_int64_t pkt_ms,
						    const u_char *data, u_int32_t datalen, u_int32_t datacaplen,
						    OutBatch &out) {
	if(saw_syn || has_seq_bound) {
		return;
	}
	if(synced && pkt_ms > created_ms && pkt_ms - created_ms > PRE_WINDOW_MS) {
		return;
	}
	u_int32_t dist = (u_int32_t)(first_seq - seq);
	if(dist > PRE_WINDOW_BYTES) {
		return;
	}

	// Trim any right overlap with already-tracked [first_seq, ...)
	if(datalen > dist) {
		datalen = dist;
		if(datacaplen > datalen) {
			datacaplen = datalen;
		}
	}
	if(!datalen) {
		return;
	}

	// Case A: stream has never synced yet and only holds partial buffered bytes at buf_seq == first_seq
	if(!synced && !pre && bufLen() > 0 && buf_seq == first_seq) {
		if(seq + datalen == first_seq) {
			bufPrepend(data, datalen, datacaplen, seq, ts, ack);
			first_seq = seq;
			bool had_hdr = false;
			u_int32_t consumed = frameBuffer<true>(buf + buf_head, bufLen(), buf_seq, msg_ts, msg_ack, out, had_hdr);
			buf_head += consumed;
			buf_seq += consumed;
			if(buf_head == buf_tail) {
				clearBuffer();
			}
			return;
		}
		// Earlier segment with a gap before buffered tail: move buffered tail into OOO and rewind stream
		u_int32_t old_len = bufLen();
		insertOoo(buf_seq, msg_ack, msg_ts, buf + buf_head, old_len, old_len, pkt_ms);
		clearBuffer();
		first_seq = seq;
		rcv_nxt = seq;
		bufAppend(data, datalen, datacaplen, seq, ts, ack);
		rcv_nxt += datalen;
		drainOoo();
		bool had_hdr = false;
		u_int32_t consumed = frameBuffer<true>(buf + buf_head, bufLen(), buf_seq, msg_ts, msg_ack, out, had_hdr);
		buf_head += consumed;
		buf_seq += consumed;
		if(buf_head == buf_tail) {
			clearBuffer();
		}
		return;
	}

	// Case B: single contiguous complete SIP message immediately before first_seq (no pre needed)
	if(!pre && !pre_tail && seq + datalen == first_seq && datacaplen == datalen) {
		bool dummy_hdr = false;
		unsigned before_out = out.size();
		u_int32_t consumed = frameBuffer<false>(data, datalen, seq, ts, ack, out, dummy_hdr);
		if(consumed == datalen && out.size() > before_out) {
			first_seq = seq;
			return;
		}
		// Roll back partial framing on fast path check? If consumed > 0, some msgs already emitted;
		// only remaining tail [consumed..datalen) stays unhandled -> fall through for tail if needed.
		if(consumed > 0) {
			data += consumed;
			seq += consumed;
			datalen -= consumed;
			datacaplen -= consumed;
			if(!datalen) {
				first_seq = seq - consumed;
				return;
			}
		}
	}

	// Case C: general cold path — allocate bounded pre DirStream covering [..., first_seq)
	if(!pre) {
		pre = new FILE_LINE(0) DirStream();
		pre->has_seq_bound = true;
		pre->max_seq_bound = first_seq;
		pre->created_ms = created_ms;
		if(pre_tail && pre_tail_seq == first_seq) {
			// Extend pre's upper bound to cover the saved unparsed head of the main stream
			pre->max_seq_bound = first_seq + pre_tail_len;
			pre->insertOoo(pre_tail_seq, ack, ts, pre_tail, pre_tail_len, pre_tail_len, pkt_ms);
			delete [] pre_tail;
			pre_tail = NULL;
			pre_tail_len = 0;
			pre_tail_seq = 0;
		}
	}
	pre->pushSegment(seq, ack, tcp_flags, ts, pkt_ms, data, datalen, datacaplen, out);
	maybeRetirePre(pkt_ms, out);
}

void TcpSipStreamEngine::DirStream::pushSegment(u_int32_t seq, u_int32_t ack, u_int8_t tcp_flags,
						timeval ts, u_int64_t pkt_ms,
						const u_char *data, u_int32_t datalen, u_int32_t datacaplen,
						OutBatch &out) {
	const bool is_syn = (tcp_flags & TH_SYN) != 0;
	const bool is_fin = (tcp_flags & TH_FIN) != 0;
	const bool is_rst = (tcp_flags & TH_RST) != 0;

	if(is_syn && !has_seq_bound) {
		if(seq_init && tcp_seq_diff(seq + 1, rcv_nxt) != 0) {
			// New TCP connection reusing the same 4-tuple
			flushAll(out);
			reset();
		}
		seq_init = true;
		saw_syn = true;
		first_seq = seq + 1;
		rcv_nxt = seq + 1;
		created_ms = pkt_ms;
		if(datalen == 0) {
			return;
		}
		seq += 1;
	}

	if(datalen == 0) {
		if(is_fin) {
			flushAll(out);
		} else if(is_rst) {
			clearOoo();
		}
		return;
	}

	if(!seq_init) {
		seq_init = true;
		first_seq = seq;
		rcv_nxt = seq;
		created_ms = pkt_ms;
	}

	if(pre || pre_tail) {
		maybeRetirePre(pkt_ms, out);
	}

	// Check pre-first_seq arrival on mid-stream wild links (parallel worker startup race)
	if(!saw_syn && !has_seq_bound && tcp_seq_lt(seq, first_seq)) {
		pushPreFirstSeq(seq, ack, tcp_flags, ts, pkt_ms, data, datalen, datacaplen, out);
		return;
	}

	if(has_seq_bound) {
		if(tcp_seq_ge(seq, max_seq_bound)) {
			return;
		}
		if(tcp_seq_gt(seq + datalen, max_seq_bound)) {
			datalen = (u_int32_t)(max_seq_bound - seq);
			if(datacaplen > datalen) {
				datacaplen = datalen;
			}
		}
	}

	int32_t diff = tcp_seq_diff(seq, rcv_nxt);

	if(diff < 0) {
		u_int32_t overlap = (u_int32_t)(-diff);
		if(overlap >= datalen) {
			// Pure duplicate / full retransmission -> instant O(1) drop!
			return;
		}
		// Partial left overlap -> trim already-delivered prefix (RFC 793)
		data += overlap;
		seq += overlap;
		datalen -= overlap;
		datacaplen = datacaplen > overlap ? (datacaplen - overlap) : 0;
		diff = 0;
	}

	if(diff == 0) {
		// In-order fast path!
		if(bufLen() == 0 && !ooo_head && datacaplen == datalen) {
			// ZERO-COPY single-segment fast path: frame directly from caller's packet buffer
			bool had_hdr = false;
			u_int32_t consumed = frameBuffer<false>(data, datalen, seq, ts, ack, out, had_hdr);
			rcv_nxt += datalen;
			if(consumed < datalen) {
				bufAppend(data + consumed, datalen - consumed, datalen - consumed, seq + consumed, ts, ack);
			}
		} else {
			bufAppend(data, datalen, datacaplen, seq, ts, ack);
			rcv_nxt += datalen;
			if(ooo_head) {
				drainOoo();
			}
			if(bufLen() > 0) {
				bool had_hdr = (hdr_total_len > 0 || hdr_scan_off > 0);
				u_int32_t consumed = frameBuffer<true>(buf + buf_head, bufLen(), buf_seq, msg_ts, msg_ack, out, had_hdr);
				buf_head += consumed;
				buf_seq += consumed;
				if(buf_head == buf_tail) {
					clearBuffer();
				}
			}
		}
		if(is_fin) {
			flushAll(out);
		}
		return;
	}

	// Out-of-order future segment (diff > 0)
	if((u_int32_t)diff > MAX_OOO_WINDOW) {
		// Huge jump (> 2 MB): capture discontinuity or missed reconnect -> resync stream
		flushAll(out);
		synced = false;
		saw_syn = false;
		created_ms = pkt_ms;
		first_seq = seq;
		rcv_nxt = seq;
		bufAppend(data, datalen, datacaplen, seq, ts, ack);
		rcv_nxt += datalen;
		bool had_hdr = false;
		u_int32_t consumed = frameBuffer<true>(buf + buf_head, bufLen(), buf_seq, msg_ts, msg_ack, out, had_hdr);
		buf_head += consumed;
		buf_seq += consumed;
		if(buf_head == buf_tail) {
			clearBuffer();
		}
		return;
	}

	insertOoo(seq, ack, ts, data, datalen, datacaplen, pkt_ms);

	// Gap recovery: if OOO queue stalls past threshold, advance past permanently dropped segment
	if(ooo_head &&
	   (ooo_count >= GAP_ADVANCE_SEGS ||
	    ooo_bytes >= GAP_ADVANCE_BYTES ||
	    (ooo_first_ms && pkt_ms > ooo_first_ms && (pkt_ms - ooo_first_ms) >= GAP_ADVANCE_MS) ||
	    is_fin)) {
		advanceGap(out);
		if(is_fin) {
			flushAll(out);
		}
	}
}


// --- Shard ---

TcpSipStreamEngine::Shard::~Shard() {
	Link *cur = lru_head;
	while(cur) {
		Link *next = cur->lru_next;
		delete cur;
		cur = next;
	}
	delete [] buckets;
	buckets = NULL;
	lru_head = NULL;
	lru_tail = NULL;
	link_count = 0;
}

void TcpSipStreamEngine::Shard::ensureBuckets() {
	if(buckets) {
		return;
	}
	u_int32_t cap = 64u;
	buckets = new FILE_LINE(0) Link*[cap];
	memset(buckets, 0, sizeof(Link*) * cap);
	bucket_mask = cap - 1;
}

void TcpSipStreamEngine::Shard::rehash() {
	u_int32_t old_cap = bucket_mask + 1;
	u_int32_t new_cap = old_cap * 2;
	Link **nb = new FILE_LINE(0) Link*[new_cap];
	memset(nb, 0, sizeof(Link*) * new_cap);
	u_int32_t new_mask = new_cap - 1;
	for(u_int32_t i = 0; i < old_cap; ++i) {
		Link *cur = buckets[i];
		while(cur) {
			Link *next = cur->hash_next;
			u_int32_t idx = (u_int32_t)((cur->hash >> 8) & new_mask);
			cur->hash_next = nb[idx];
			nb[idx] = cur;
			cur = next;
		}
	}
	delete [] buckets;
	buckets = nb;
	bucket_mask = new_mask;
}

TcpSipStreamEngine::Link *TcpSipStreamEngine::Shard::find(const LinkKey &key, u_int64_t hash) {
	if(!buckets) {
		return NULL;
	}
	u_int32_t idx = (u_int32_t)((hash >> 8) & bucket_mask);
	Link *cur = buckets[idx];
	while(cur) {
		if(cur->hash == hash && cur->key == key) {
			return cur;
		}
		cur = cur->hash_next;
	}
	return NULL;
}

void TcpSipStreamEngine::Shard::insert(Link *link) {
	ensureBuckets();
	if(link_count >= (bucket_mask + 1) * 2) {
		rehash();
	}
	u_int32_t idx = (u_int32_t)((link->hash >> 8) & bucket_mask);
	link->hash_next = buckets[idx];
	buckets[idx] = link;
	// Push to LRU head
	link->lru_prev = NULL;
	link->lru_next = lru_head;
	if(lru_head) {
		lru_head->lru_prev = link;
	} else {
		lru_tail = link;
	}
	lru_head = link;
	++link_count;
}

void TcpSipStreamEngine::Shard::unlink(Link *link) {
	u_int32_t idx = (u_int32_t)((link->hash >> 8) & bucket_mask);
	Link **pp = &buckets[idx];
	while(*pp) {
		if(*pp == link) {
			*pp = link->hash_next;
			break;
		}
		pp = &((*pp)->hash_next);
	}
	link->hash_next = NULL;
	if(link->lru_prev) {
		link->lru_prev->lru_next = link->lru_next;
	} else {
		lru_head = link->lru_next;
	}
	if(link->lru_next) {
		link->lru_next->lru_prev = link->lru_prev;
	} else {
		lru_tail = link->lru_prev;
	}
	link->lru_prev = NULL;
	link->lru_next = NULL;
	--link_count;
}

void TcpSipStreamEngine::Shard::touchLru(Link *link) {
	if(lru_head == link) {
		return;
	}
	if(link->lru_prev) {
		link->lru_prev->lru_next = link->lru_next;
	}
	if(link->lru_next) {
		link->lru_next->lru_prev = link->lru_prev;
	} else {
		lru_tail = link->lru_prev;
	}
	link->lru_prev = NULL;
	link->lru_next = lru_head;
	if(lru_head) {
		lru_head->lru_prev = link;
	} else {
		lru_tail = link;
	}
	lru_head = link;
}


// --- TcpSipStreamEngine ---

TcpSipStreamEngine::TcpSipStreamEngine(TcpReassembly *owner)
	: owner(owner), stat_links(0) {
}

TcpSipStreamEngine::~TcpSipStreamEngine() {
}

void TcpSipStreamEngine::evictExpiredLocked(Shard &sh, u_int64_t now_ms, u_int64_t timeout_ms,
					    bool all, std::vector<FlushMeta*> *flushed) {
	TcpReassemblyProcessData *cb = owner ? owner->getDataCallback() : NULL;
	Link *link = sh.lru_tail;
	while(link) {
		Link *prev = link->lru_prev;
		if(!all) {
			if(now_ms <= link->last_time_ms || (now_ms - link->last_time_ms) <= timeout_ms) {
				break;
			}
			if(!link->skip_ws_inflate_timeout && cb &&
			   cb->existsWebSocketInflateContext(link->key.ip_lo, link->key.ip_hi, link->key.port_lo, link->key.port_hi)) {
				u_int64_t ws_timeout_ms = (u_int64_t)WEBSOCKET_INFLATE_LINK_TIMEOUT * 1000ULL;
				if(ws_timeout_ms > timeout_ms && (now_ms - link->last_time_ms) <= ws_timeout_ms) {
					link = prev;
					continue;
				}
			}
		}
		sh.unlink(link);
		__SYNC_DEC(stat_links);
		if(flushed) {
			for(int d = 0; d < 2; ++d) {
				if(link->dirs[d].bufLen() > 0 || link->dirs[d].ooo_head || link->dirs[d].pre) {
					FlushMeta *fm = new FILE_LINE(0) FlushMeta();
					link->dirs[d].flushAll(fm->batch);
					if(fm->batch.size() > 0) {
						if(d == 0) {
							fm->ip_src = link->key.ip_lo;
							fm->ip_dst = link->key.ip_hi;
							fm->port_src = link->key.port_lo;
							fm->port_dst = link->key.port_hi;
						} else {
							fm->ip_src = link->key.ip_hi;
							fm->ip_dst = link->key.ip_lo;
							fm->port_src = link->key.port_hi;
							fm->port_dst = link->key.port_lo;
						}
						fm->eth_header_len = link->eth_header_len;
						if(fm->eth_header_len) {
							memcpy(fm->eth_header, link->eth_header, fm->eth_header_len);
						}
						fm->handle_index = link->handle_index;
						fm->dlt = link->dlt;
						fm->sensor_id = link->sensor_id;
						fm->sensor_ip = link->sensor_ip;
						fm->pid = link->pid;
						flushed->push_back(fm);
					} else {
						delete fm;
					}
				}
			}
		}
		delete link;
		link = prev;
	}
}

void TcpSipStreamEngine::dispatchFlushed(std::vector<FlushMeta*> &flushed, void *uData, void *uData2) {
	if(flushed.empty()) {
		return;
	}
	SipTcpData *sipCb = static_cast<SipTcpData*>(owner->getDataCallback());
	for(size_t i = 0; i < flushed.size(); ++i) {
		FlushMeta *fm = flushed[i];
		if(sipCb) {
			for(unsigned j = 0; j < fm->batch.size(); ++j) {
				const OutMsg &m = fm->batch.at(j);
				sipCb->dispatchSipMessage(fm->ip_src, fm->ip_dst, fm->port_src, fm->port_dst,
							  const_cast<u_char*>(m.ptr), m.len,
							  m.seq, m.ack, m.ts,
							  fm->eth_header, fm->eth_header_len,
							  fm->handle_index, fm->dlt, fm->sensor_id, fm->sensor_ip, fm->pid,
							  uData, uData2, NULL);
			}
		}
		delete fm;
	}
	flushed.clear();
}

void TcpSipStreamEngine::push(pcap_pkthdr *header, iphdr2 *header_ip, u_char *packet,
			      u_int16_t handle_index, int dlt, int sensor_id, vmIP sensor_ip, sPacketInfoData pid,
			      void *uData, void *uData2) {
	tcphdr2 *header_tcp_ptr = NULL;
	u_char *data = NULL;
	u_int32_t datalen = 0;
	u_int32_t datacaplen = 0;
	if(!TcpReassembly::extractTcpSegment(header, header_ip, packet, &header_tcp_ptr, &data, &datalen, &datacaplen)) {
		return;
	}

	vmIP ip_src = header_ip->get_saddr();
	vmIP ip_dst = header_ip->get_daddr();
	u_int16_t port_src = header_tcp_ptr->get_source();
	u_int16_t port_dst = header_tcp_ptr->get_dest();
	u_int32_t seq = ntohl(header_tcp_ptr->seq);
	u_int32_t ack = ntohl(header_tcp_ptr->ack_seq);
	u_int8_t tcp_flags = header_tcp_ptr->flags;

	if(sverb.tcp_debug_port) {
		if((int)port_src != sverb.tcp_debug_port && (int)port_dst != sverb.tcp_debug_port) {
			return;
		}
	}
	vmIP *tcp_debug_ip = (vmIP*)sverb.tcp_debug_ip;
	if(tcp_debug_ip->isSet()) {
		if(ip_src != *tcp_debug_ip && ip_dst != *tcp_debug_ip) {
			return;
		}
	}

	LinkKey key;
	int dir = 0;
	makeCanonicalKey(ip_src, port_src, ip_dst, port_dst, key, dir);
	u_int64_t h = hashLinkKey(key);
	Shard &sh = shards[h & (NUM_SHARDS - 1)];

	u_int64_t pkt_ms = getTimeMS(header);
	OutBatch out;
	u_char eth_header[50];
	u_int32_t eth_header_len = 0;
	bool do_destroy_ws_inflate = false;
	std::vector<FlushMeta*> flushed;

	sh.lock.lock(1);

	if(pkt_ms > sh.act_time_ms) {
		sh.act_time_ms = pkt_ms;
	}

	Link *link = sh.find(key, h);
	if(!link) {
		if(datalen == 0 && !(tcp_flags & TH_SYN)) {
			// Avoid allocating link state for stray pure-ACK / FIN / RST packets
			sh.lock.unlock();
			return;
		}
		link = new FILE_LINE(0) Link(key, h);
		link->last_time_ms = pkt_ms;
		link->handle_index = handle_index;
		link->dlt = dlt;
		link->sensor_id = sensor_id;
		link->sensor_ip = sensor_ip;
		link->pid = pid;
		u_int16_t h_ip_off = 0, h_proto = 0, h_vlan = 0;
		if(parseEtherHeader(dlt, packet, NULL, NULL, h_ip_off, h_proto, h_vlan) &&
		   h_ip_off > 0 && h_ip_off < 50) {
			link->eth_header_len = h_ip_off;
			memcpy(link->eth_header, packet, h_ip_off);
		}
		sh.insert(link);
		__SYNC_INC(stat_links);
	} else {
		if(pkt_ms > link->last_time_ms + 1000ULL) {
			link->last_time_ms = pkt_ms;
			sh.touchLru(link);
		}
	}

	if((tcp_flags & TH_SYN) && !(tcp_flags & TH_ACK)) {
		link->skip_ws_inflate_timeout = false;
		do_destroy_ws_inflate = true;
	} else if(tcp_flags & (TH_FIN | TH_RST)) {
		link->skip_ws_inflate_timeout = true;
	}

	if(datalen > 0 || (tcp_flags & (TH_SYN | TH_FIN | TH_RST))) {
		link->dirs[dir].pushSegment(seq, ack, tcp_flags, header->ts, pkt_ms, data, datalen, datacaplen, out);
		if(out.size() > 0) {
			eth_header_len = link->eth_header_len;
			if(eth_header_len) {
				memcpy(eth_header, link->eth_header, eth_header_len);
			}
		}
	}

	// Lazy per-shard LRU tail expiration (O(expired), zero global lock)
	u_int64_t timeout_ms = (u_int64_t)owner->getLinkTimeout() * 1000ULL;
	if(timeout_ms > 0 && sh.act_time_ms > sh.last_cleanup_ms + 2000ULL) {
		sh.last_cleanup_ms = sh.act_time_ms;
		evictExpiredLocked(sh, sh.act_time_ms, timeout_ms, false, &flushed);
	}

	sh.lock.unlock();

	// Perform all downstream callbacks strictly AFTER releasing shard lock!
	SipTcpData *sipCb = static_cast<SipTcpData*>(owner->getDataCallback());
	if(do_destroy_ws_inflate && sipCb) {
		sipCb->destroyWebSocketInflate(ip_src, ip_dst, port_src, port_dst);
	}
	if(sipCb && out.size() > 0) {
		for(unsigned i = 0; i < out.size(); ++i) {
			const OutMsg &m = out.at(i);
			sipCb->dispatchSipMessage(ip_src, ip_dst, port_src, port_dst,
						  const_cast<u_char*>(m.ptr), m.len,
						  m.seq, m.ack, m.ts,
						  eth_header, eth_header_len,
						  handle_index, dlt, sensor_id, sensor_ip, pid,
						  uData, uData2, NULL);
		}
	}
	if(!flushed.empty()) {
		dispatchFlushed(flushed, uData, uData2);
	}
}

void TcpSipStreamEngine::cleanup(bool all) {
	u_int64_t max_time_ms = 0;
	if(!all) {
		for(unsigned s = 0; s < NUM_SHARDS; ++s) {
			shards[s].lock.lock(1);
			if(shards[s].act_time_ms > max_time_ms) {
				max_time_ms = shards[s].act_time_ms;
			}
			shards[s].lock.unlock();
		}
	}
	u_int64_t timeout_ms = (u_int64_t)owner->getLinkTimeout() * 1000ULL;
	std::vector<FlushMeta*> flushed;
	for(unsigned s = 0; s < NUM_SHARDS; ++s) {
		shards[s].lock.lock(1);
		evictExpiredLocked(shards[s], max_time_ms, timeout_ms, all, &flushed);
		shards[s].lock.unlock();
		if(!flushed.empty()) {
			dispatchFlushed(flushed, NULL, NULL);
		}
	}
}

void TcpSipStreamEngine::getStats(u_int32_t &links, u_int32_t &buffered_dirs, u_int32_t &ooo_segs) const {
	links = __SYNC_ADD(const_cast<volatile u_int32_t&>(stat_links), 0);
	buffered_dirs = 0;
	ooo_segs = 0;
}

size_t TcpSipStreamEngine::getLinkCount() const {
	return (size_t)__SYNC_ADD(const_cast<volatile u_int32_t&>(stat_links), 0);
}
