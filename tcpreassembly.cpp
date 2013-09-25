#include <iomanip>
#include <iostream>
#include <algorithm>
#include <sstream>

#include "tcpreassembly.h"
#include "sql_db.h"
#include "tools.h"

using namespace std;


#define ENABLE_UNLOCK_PACKET_IN_OK false

extern char opt_tcpreassembly_log[1024];
extern char opt_pb_read_from_file[256];
extern int terminating;

bool globalDebug = false;
bool debug_packet = globalDebug && true;
bool debug_rslt = globalDebug && true;
bool debug_data = globalDebug && true;
bool debug_check_ok = globalDebug && true;
bool debug_check_ok_process = globalDebug && true;
bool debug_save = globalDebug && true;
bool debug_print_content = globalDebug && true;
u_int16_t debug_counter = 0;
u_int16_t debug_limit_counter = 0;
u_int16_t debug_port = 0;
// dořešit:
// /home/jumbox/Plocha/http_pcaps/http_00684_20130903072226.pcap / 49668 - data jsou komplet i když je příznak expect continue - odpověď na expoct continue pak jde se stejným ack jako finální odpověď
u_int32_t debug_seq = 0;


bool TcpReassemblyData::isFill() {
	return(this->request.size());
}


void TcpReassemblyStream_packet_var::push(TcpReassemblyStream_packet packet) {
	map<uint32_t, TcpReassemblyStream_packet>::iterator iter;
	iter = this->queue.find(packet.next_seq);
	if(iter == this->queue.end()) {
		this->queue[packet.next_seq];
		this->queue[packet.next_seq] = packet;
		if(opt_tcpreassembly_pb_lock) {
			packet.lock_packet();
		}
	}
}

void TcpReassemblyStream::push(TcpReassemblyStream_packet packet) {
	map<uint32_t, TcpReassemblyStream_packet_var>::iterator iter;
	iter = this->queue.find(packet.header_tcp.seq);
	if(debug_seq && packet.header_tcp.seq == debug_seq) {
		cout << " -- XXX DEBUG SEQ XXX" << endl;
	}
	this->queue[packet.header_tcp.seq].push(packet);
	if(packet.datalen) {
		exists_data = true;
	}
	this->last_packet_at_from_header = packet.time.tv_sec * 1000 + packet.time.tv_usec / 1000;
}

int TcpReassemblyStream::ok(bool crazySequence, bool enableSimpleCmpMaxNextSeq, u_int32_t maxNextSeq,
			    bool enableCheckCompleteContent, TcpReassemblyStream *prevHttpStream, bool enableDebug) {
	if(this->is_ok) {
		return(1);
	}
	this->cleanPacketsState();
	if(!this->queue.begin()->second.getNextSeqCheck()) {
		if(enableDebug) {
			cout << " --- ERR - reassembly failed (1)";
		}
		return(0);
	}
	map<uint32_t, TcpReassemblyStream_packet_var>::iterator iter_var;
	int _counter = 0;
	bool waitForPsh = this->_only_check_psh ? true : false;
	while(true) {
		u_int32_t seq = this->ok_packets.size() ? 
					this->ok_packets.back()[1] : 
					(crazySequence ? this->min_seq : this->first_seq);
		iter_var = this->queue.find(seq);
		if(iter_var == this->queue.end() && this->ok_packets.size()) {
			u_int32_t prev_seq = this->ok_packets.back()[0];
			map<uint32_t, TcpReassemblyStream_packet_var>::iterator temp_iter;
			for(temp_iter = this->queue.begin(); temp_iter != this->queue.end(); temp_iter++) {
				if(temp_iter->first > prev_seq && temp_iter->first < seq) {
					iter_var = temp_iter;
					break;
				}
			}
		}
		if(iter_var == this->queue.end()) {
			if(!this->ok_packets.size()) {
				if(enableDebug) {
					cout << " --- ERR - reassembly failed (2)";
				}
				return(0);
			} else {
				this->queue[this->ok_packets.back()[0]].queue[this->ok_packets.back()[1]].state = TcpReassemblyStream_packet::FAIL;
				this->ok_packets.pop_back();
				if(enableDebug) {
					cout << "<";
				}
			}
		} else {
			u_int32_t next_seq = iter_var->second.getNextSeqCheck();
			if(next_seq) {
				this->ok_packets.push_back(d_u_int32_t(iter_var->first, next_seq));
				if(enableCheckCompleteContent) {
					this->saveCompleteData(false, true, prevHttpStream);
					if(this->http_ok) {
						this->is_ok = true;
						this->completed = true;
						if(opt_tcpreassembly_pb_lock && ENABLE_UNLOCK_PACKET_IN_OK) {
							this->unlockPackets();
						}
						this->detect_ok_max_next_seq = next_seq;
						return(1);
					} else {
						this->clearCompleteData();
					}
				}
				this->queue[this->ok_packets.back()[0]].queue[this->ok_packets.back()[1]].state = TcpReassemblyStream_packet::CHECK;
				if(enableDebug) {
					cout << "-";
				}
				if(waitForPsh ?
				    this->queue[this->ok_packets.back()[0]].queue[this->ok_packets.back()[1]].header_tcp.psh :
				    ((maxNextSeq && next_seq == maxNextSeq) ||
				     (maxNextSeq && next_seq == maxNextSeq - 1) ||
				     (this->last_seq && next_seq == this->last_seq) ||
				     (this->last_seq && next_seq == this->last_seq - 1) ||
				     (enableSimpleCmpMaxNextSeq && next_seq == this->max_next_seq) ||
				     (!crazySequence && next_seq == this->max_next_seq && next_seq == this->getLastSeqFromNextStream()))) {
					if(!this->queue[this->ok_packets.back()[0]].queue[this->ok_packets.back()[1]].header_tcp.psh) {
						waitForPsh = true;
					} else {
						if(!waitForPsh && this->_force_wait_for_next_psh) {
							waitForPsh = true;
						} else {
							this->is_ok = true;
							this->saveCompleteData(ENABLE_UNLOCK_PACKET_IN_OK);
							if(!this->_force_wait_for_next_psh) {
								this->detect_ok_max_next_seq = next_seq;
							}
							return(1);
						}
					}
				} else if(enableDebug && debug_check_ok_process) {
					cout << "  "
					     << "next_seq: " << next_seq << " !== "
					     << "last_seq: " << (this->last_seq ? this->last_seq : maxNextSeq)
					     << "  ";
				}
			} else if(this->ok_packets.size()) {
				this->queue[this->ok_packets.back()[0]].queue[this->ok_packets.back()[1]].state = TcpReassemblyStream_packet::FAIL;
				this->ok_packets.pop_back();
				if(enableDebug) {
					cout << "<";
				}
			} else {
				if(enableDebug) {
					cout << " --- ERR - reassembly failed (3)";
				}
				return(0);
			}
		}
		if(++_counter > 500) {
			break;
		}
	}
	if(enableDebug) {
		cout << " --- ERR - reassembly failed (4)";
	}
	return(0);
}

bool TcpReassemblyStream::ok2_ec(u_int32_t nextAck, bool enableDebug) {
        map<uint32_t, TcpReassemblyStream*>::iterator iter;
	iter = this->link->queue_by_ack.find(nextAck);
	if(iter == this->link->queue_by_ack.end()) {
		return(false);
	}
	TcpReassemblyStream *nextStream = iter->second;
	
	/*
	if(this->ack == 766596997) {
		cout << "-- ***** --";
	}
	*/
 
	nextStream->_only_check_psh = true;
	if(!nextStream->ok(true, false, 0,
			   false, NULL, enableDebug)) {
		return(false);
	}
	this->_force_wait_for_next_psh = true;
	if(!this->ok(true, false, this->detect_ok_max_next_seq,
		     false, NULL, enableDebug)) {
		nextStream->is_ok = false;
		nextStream->clearCompleteData();
		return(false);
	}
	if(this->checkOkPost(nextStream)) {
		this->http_ok_expect_continue_post = true;
		nextStream->http_ok_expect_continue_data = true;
		return(true);
	} else {
		nextStream->is_ok = false;
		nextStream->clearCompleteData();
		this->is_ok = false;
		this->clearCompleteData();
		return(false);
	}
	return(false);
}

u_char *TcpReassemblyStream::complete(u_int32_t *datalen, timeval *time, bool check, bool unlockPackets) {
	if(!check && !this->is_ok) {
		*datalen = 0;
		this->completed = true;
		return(NULL);
	}
	u_char *data = NULL;
	*datalen = 0;
	time->tv_sec = 0;
	time->tv_usec = 0;
	u_int32_t databuff_len = 0;
	u_int32_t lastNextSeq = 0;
	for(size_t i = 0; i < this->ok_packets.size(); i++) {
		TcpReassemblyStream_packet packet = this->queue[this->ok_packets[i][0]].queue[this->ok_packets[i][1]];
		if(packet.datalen) {
			if(lastNextSeq > this->ok_packets[i][0]) {
				*datalen -= lastNextSeq - this->ok_packets[i][0];
			}
			if(!time->tv_sec) {
				*time = packet.time;
			}
			if(!data) {
				databuff_len = max(packet.datalen + 1, 10000u);
				data = new u_char[databuff_len];
				
			} else if(databuff_len < *datalen + packet.datalen) {
				databuff_len = max(*datalen, databuff_len) + max(packet.datalen + 1, 10000u);
				u_char* newdata = new u_char[databuff_len];
				memcpy(newdata, data, *datalen);
				delete [] data;
				data = newdata;
			}
			memcpy(data + *datalen, packet.data, min(packet.datalen, packet.datacaplen));
			if(packet.datacaplen < packet.datalen) {
				memset(data + *datalen + packet.datacaplen, ' ', packet.datalen - packet.datacaplen);
			}
			*datalen += packet.datalen;
			lastNextSeq = this->ok_packets[i][1];
		}
	}
	if(*datalen) {
		data[*datalen] = 0;
	}
	if(!check) {
		this->completed = true;
		if(opt_tcpreassembly_pb_lock && unlockPackets) {
			this->unlockPackets();
		}
	}
	return(data);
}

bool TcpReassemblyStream::saveCompleteData(bool unlockPackets, bool check, TcpReassemblyStream *prevHttpStream) {
	if(this->is_ok || check) {
		if(this->complete_data.isFill()) {
			return(true);
		} else {
			u_char *data;
			u_int32_t datalen;
			timeval time;
			data = this->complete(&datalen, &time, check, unlockPackets);
			if(data) {
				this->complete_data.setDataTime(data, datalen, time, false);
				if(datalen > 5 && !memcmp(data, "POST ", 5)) {
					this->http_type = HTTP_TYPE_POST;
				} else if(datalen > 4 && !memcmp(data, "GET ", 4)) {
					this->http_type = HTTP_TYPE_GET;
				} else if(datalen > 5 && !memcmp(data, "HEAD ", 5)) {
					this->http_type = HTTP_TYPE_HEAD;
				} else if(datalen > 4 && !memcmp(data, "HTTP", 4)) {
					this->http_type = HTTP_TYPE_HTTP;
				}
				this->http_header_length = 0;
				this->http_content_length = 0;
				this->http_ok = false;
				this->http_ok_data_complete = false;
				this->http_expect_continue = false;
				if(this->http_type) {
					char *pointToContentLength = strcasestr((char*)data, "Content-Length:");
					if(pointToContentLength) {
						this->http_content_length = atol(pointToContentLength + 15);
					}
					char *pointToEndHeader = strstr((char*)data, "\r\n\r\n");
					if(pointToEndHeader) {
						this->http_header_length = (u_char*)pointToEndHeader - data;
						if(this->http_content_length) {
							if(!this->_ignore_expect_continue &&
							   strcasestr((char*)data, "Expect: 100-continue")) {
								if(((u_char*)pointToEndHeader - data) + 4 == datalen) {
									this->http_ok = true;
								} else if(((u_char*)pointToEndHeader - data) + 4 + http_content_length == datalen) {
									this->http_ok = true;
									this->http_ok_data_complete = true;
								}
								this->http_expect_continue = true;
							} else if(((u_char*)pointToEndHeader - data) + 4 + http_content_length == datalen) {
								this->http_ok = true;
							}
						} else {
							if(((u_char*)pointToEndHeader - data) + 4 == datalen) {
								this->http_ok = true;
							}
						}
					}
				} else if(prevHttpStream && prevHttpStream->http_type == HTTP_TYPE_POST && prevHttpStream->http_expect_continue) {
					if(datalen == prevHttpStream->http_content_length) {
						this->http_ok = true;
						this->http_ok_data_complete = true;
					}
				}
				return(true);
			}
		}
	}
	return(false);
}

void TcpReassemblyStream::clearCompleteData() {
	this->complete_data.clearData();
}

void TcpReassemblyStream::unlockPackets() {
	if(opt_tcpreassembly_pb_lock) {
		map<uint32_t, TcpReassemblyStream_packet_var>::iterator iter;
		for(iter = this->queue.begin(); iter != this->queue.end(); iter++) {
			this->queue[iter->first].unlockPackets();
		}
	}
}

void TcpReassemblyStream::printContent(int level) {
	map<uint32_t, TcpReassemblyStream_packet_var>::iterator iter;
	int counter = 0;
	for(iter = this->queue.begin(); iter != this->queue.end(); iter++) {
		cout << fixed 
		     << setw(level * 5) << ""
		     << setw(3) << (++counter) << "   " 
		     << "ack: " << iter->first
		     << " items: " << iter->second.queue.size()
		     << endl;
	}
}

bool TcpReassemblyStream::checkOkPost(TcpReassemblyStream *nextStream) {
	if(!this->complete_data.getData()) {
		return(false);
	}
	bool rslt = false;
	u_int32_t datalen = this->complete_data.getDatalen();
	bool useNextStream = false;
	if(nextStream && nextStream->complete_data.getData()) {
		datalen += nextStream->complete_data.getDatalen();
		useNextStream = true;
	}
	char *data = new char[datalen + 1];
	memcpy(data, this->complete_data.getData(), this->complete_data.getDatalen());
	if(useNextStream) {
		memcpy(data + this->complete_data.getDatalen(), nextStream->complete_data.getData(), nextStream->complete_data.getDatalen());
	}
	data[datalen] = 0;
	if(datalen > 5 && !memcmp(data, "POST ", 5)) {
		this->http_type = HTTP_TYPE_POST;
		char *pointToContentLength = strcasestr((char*)data, "Content-Length:");
		this->http_content_length = pointToContentLength ? atol(pointToContentLength + 15) : 0;
		char *pointToEndHeader = strstr((char*)data, "\r\n\r\n");
		if(pointToEndHeader &&
		   (pointToEndHeader - data) + 4 + this->http_content_length == datalen) {
			this->http_ok = true;
			rslt = true;
		}
	}
	delete [] data;
	return(rslt);
	
}

/*
bool TcpReassemblyStream::checkCompleteContent() {
	if(!this->complete_data) {
		return(false);
	}
	u_char *data = this->complete_data->data;
	u_int32_t datalen = this->complete_data->datalen;
	bool http = (datalen > 5 && !memcmp(data, "POST ", 5)) ||
		    (datalen > 4 && !memcmp(data, "GET ", 4)) ||
		    (datalen > 5 && !memcmp(data, "HEAD ", 5));
	if(http) {
		if(!memcmp(data + datalen - 4, "\r\n\r\n", 4)) {
			return(true);
		}
	}
	return(false);
}

bool TcpReassemblyStream::checkContentIsHttpRequest() {
	if(!this->complete_data) {
		return(false);
	}
	u_char *data = this->complete_data->data;
	u_int32_t datalen = this->complete_data->datalen;
	bool http = (datalen > 5 && !memcmp(data, "POST ", 5)) ||
		    (datalen > 4 && !memcmp(data, "GET ", 4)) ||
		    (datalen > 5 && !memcmp(data, "HEAD ", 5));
	if(http) {
		return(true);
	}
	return(false);
}
*/

u_int32_t TcpReassemblyStream::getLastSeqFromNextStream() {
	TcpReassemblyStream *stream = this->link->findStreamBySeq(this->ack);
	if(stream) {
		return(stream->ack);
	}
	return(0);
}


bool TcpReassemblyLink::streamIterator::init() {
	this->stream = NULL;
	this->state = STATE_NA;
	if(this->findSynSent()) {
		return(true);
	}
	return(this->findFirstDataToDest());
}

bool TcpReassemblyLink::streamIterator::next() {
	map<uint32_t, TcpReassemblyStream*>::iterator iter;
	TcpReassemblyStream *stream;
	switch(this->state) {
	case STATE_SYN_SENT:
		iter = link->queue_flags_by_ack.find(this->stream->min_seq + 1);
		if(iter != link->queue_flags_by_ack.end()) {
			this->stream = iter->second;
			this->state = STATE_SYN_RECV;
			return(true);
		} else {
			return(this->findFirstDataToDest());
		}
		break;
	case STATE_SYN_RECV:
		iter = link->queue_by_ack.find(this->stream->min_seq + 1);
		if(iter != link->queue_by_ack.end()) {
			this->stream = iter->second;
			this->state = STATE_SYN_OK;
			return(true);
		} else {
			return(this->findFirstDataToDest());
		}
		break;
	case STATE_SYN_OK:
	case STATE_SYN_FORCE_OK:
		stream = link->findStreamByMinSeq(this->stream->ack);
		if(stream &&
		   stream->ack != this->stream->min_seq) {
			this->stream = stream;
			this->state = STATE_SYN_OK;
			return(true);
		}
		break;
	default:
		break;
	}
	return(false);
}

bool TcpReassemblyLink::streamIterator::nextAckInDirection() {
	map<uint32_t, TcpReassemblyStream*>::iterator iter;
	for(iter = link->queue_by_ack.begin(); iter != link->queue_by_ack.end(); iter++) {
		if(iter->second->direction == this->stream->direction &&
		   iter->second->ack > this->stream->ack) {
			this->stream = iter->second;
			return(true);
		}
	}
	return(false);
}

bool TcpReassemblyLink::streamIterator::nextAckInReverseDirection() {
	map<uint32_t, TcpReassemblyStream*>::iterator iter;
	for(iter = link->queue_by_ack.begin(); iter != link->queue_by_ack.end(); iter++) {
		if(iter->second->direction != this->stream->direction &&
		   iter->second->ack > this->stream->max_next_seq) {
			this->stream = iter->second;
			return(true);
		}
	}
	return(false);
}

bool TcpReassemblyLink::streamIterator::nextSeqInDirection() {
	TcpReassemblyStream *stream = this->link->findStreamByMinSeq(this->stream->max_next_seq, true);
	if(stream && 
	   stream->direction == this->stream->direction) {
		this->stream = stream;
		return(true);
	}
	return(false);
}

void TcpReassemblyLink::streamIterator::print() {
	cout << "iterator";
	if(this->stream) {
		cout << "  ack: " << this->stream->ack
		     << "  state: " << this->state;
	} else {
		cout << " - no stream";
	}
}

u_int32_t TcpReassemblyLink::streamIterator::getMaxNextSeq() {
	TcpReassemblyStream *stream = link->findStreamByMinSeq(this->stream->ack);
	if(stream) {
		return(stream->ack);
	}
	stream = link->findStreamByMinSeq(this->stream->max_next_seq, true, this->stream->ack, this->stream->direction);
	if(stream) {
		return(stream->min_seq);
	}
	stream = link->findFlagStreamByAck(this->stream->ack);
	if(stream) {
		return(stream->min_seq);
	}
	/* disabled for crazy
	stream = link->findFinalFlagStreamByAck(this->stream->max_next_seq, 
						this->stream->direction == TcpReassemblyStream::DIRECTION_TO_DEST ? 
							TcpReassemblyStream::DIRECTION_TO_SOURCE : 
							TcpReassemblyStream::DIRECTION_TO_DEST);
	if(stream) {
		return(this->stream->max_next_seq);
	}
	stream = link->findFinalFlagStreamBySeq(this->stream->min_seq, this->stream->direction);
	if(stream) {
		return(stream->min_seq);
	}
	*/
	return(0);
}

bool TcpReassemblyLink::streamIterator::findSynSent() {
	map<uint32_t, TcpReassemblyStream*>::iterator iter;
	for(iter = link->queue_flags_by_ack.begin(); iter != link->queue_flags_by_ack.end(); iter++) {
		if(iter->second->type == TcpReassemblyStream::TYPE_SYN_SENT) {
			this->stream = iter->second;
			this->state = STATE_SYN_SENT;
			return(true);
		}
	}
	return(false);
}

bool TcpReassemblyLink::streamIterator::findFirstDataToDest() {
	map<uint32_t, TcpReassemblyStream*>::iterator iter;
	for(iter = link->queue_by_ack.begin(); iter != link->queue_by_ack.end(); iter++) {
		if(iter->second->direction == TcpReassemblyStream::DIRECTION_TO_DEST &&
		   iter->second->type == TcpReassemblyStream::TYPE_DATA) {
			this->stream = iter->second;
			this->state = STATE_SYN_FORCE_OK;
			return(true);
		}
	}
	return(false);
}


TcpReassemblyLink::~TcpReassemblyLink() {
	this->lock_queue();
	while(this->queue.size()) {
		TcpReassemblyStream *stream = this->queue.front();
		this->queue.pop_front();
		this->queue_by_ack.erase(stream->ack);
		if(debug_packet) {
			cout << " destroy (" << stream->ack << ")" << endl;
		}
		delete stream;
	}
	map<uint32_t, TcpReassemblyStream*>::iterator iter;
	for(iter = this->queue_by_ack.begin(); iter != this->queue_by_ack.end(); ) {
		delete iter->second;
		this->queue_by_ack.erase(iter++);
	}
	for(iter = this->queue_flags_by_ack.begin(); iter != this->queue_flags_by_ack.end(); ) {
		delete iter->second;
		this->queue_flags_by_ack.erase(iter++);
	}
	for(iter = this->queue_nul_by_ack.begin(); iter != this->queue_nul_by_ack.end(); ) {
		delete iter->second;
		this->queue_nul_by_ack.erase(iter++);
	}
	this->unlock_queue();
}

/*
bool TcpReassemblyLink::push_normal(
			TcpReassemblyStream::eDirection direction,
			timeval time, tcphdr header_tcp, 
			u_char *data, u_int32_t datalen, u_int32_t datacaplen,
			pcap_block_store *block_store, int block_store_index) {
	bool rslt = false;
	switch(this->state) {
	case STATE_NA:
		if(direction == TcpReassemblyStream::DIRECTION_TO_DEST &&
		   header_tcp.syn && !header_tcp.ack) {
			this->first_seq_to_dest = header_tcp.seq + 1;
			this->state = STATE_SYN_SENT;
			rslt = true;
		}
		break;
	case STATE_SYN_SENT:
		if(direction == TcpReassemblyStream::DIRECTION_TO_SOURCE &&
		   header_tcp.syn && header_tcp.ack) {
			this->first_seq_to_source = header_tcp.seq + 1;
			this->state = STATE_SYN_RECV;
			rslt = true;
		}
		break;
	case STATE_SYN_RECV:
		if(direction == TcpReassemblyStream::DIRECTION_TO_DEST &&
		   !header_tcp.syn && header_tcp.ack) {
			this->state = STATE_SYN_OK;
			rslt = true;
		}
		break;
	case STATE_SYN_OK:
	case STATE_SYN_FORCE_OK:
		if(header_tcp.rst) {
			this->rst = true;
			this->state = STATE_RESET;
			rslt = true;
		}
	case STATE_RESET:
		if(header_tcp.fin) {
			if(direction == TcpReassemblyStream::DIRECTION_TO_DEST) {
				this->fin_to_dest = true;
				this->setLastSeq(TcpReassemblyStream::DIRECTION_TO_SOURCE, 
						 header_tcp.ack_seq);
			} else {
				this->fin_to_source = true;
				this->setLastSeq(TcpReassemblyStream::DIRECTION_TO_SOURCE, 
						 header_tcp.seq);
			}
			if(this->fin_to_dest && this->fin_to_source) {
				this->state = STATE_CLOSE;
			}
			rslt = true;
		}
		break;
	case STATE_CLOSE:
	case STATE_CLOSED:
		if(this->rst && header_tcp.fin &&
		   direction == TcpReassemblyStream::DIRECTION_TO_SOURCE) {
			this->setLastSeq(TcpReassemblyStream::DIRECTION_TO_SOURCE, 
					 header_tcp.seq);
		}
		rslt = true;
		break;
	case STATE_CRAZY:
		return(false);
	}
	if(state == STATE_SYN_OK || 
	   state == STATE_SYN_FORCE_OK ||
	   (state >= STATE_RESET &&
	    !header_tcp.fin && !header_tcp.rst)) {
		if(datalen > 0) {
			TcpReassemblyStream_packet packet;
			packet.time = time;
			packet.header_tcp = header_tcp;
			packet.next_seq = packet.header_tcp.seq + datalen;
			packet.data = data;
			packet.datalen = datalen;
			packet.datacaplen = datacaplen;
			packet.block_store = block_store;
			packet.block_store_index = block_store_index;
			this->pushpacket(direction, packet);
			if(debug_packet) {
				cout << " -- DATA" << endl;
			}
		} else {
			if(this->last_ack && header_tcp.ack != this->last_ack) {
				TcpReassemblyStream *prevStreamByLastAck = this->queue_by_ack[this->last_ack];
				if(prevStreamByLastAck && !prevStreamByLastAck->last_seq &&
					prevStreamByLastAck->direction == direction) {
					prevStreamByLastAck->last_seq = header_tcp.seq;
				}
			}
		}
		rslt = true;
	}
	if(this->state == STATE_RESET || this->state == STATE_CLOSE) {
		if(debug_check_ok && this->queue.size()) {
			cout << " ";
		}
		int rslt_check_ok = this->okQueue(false, debug_check_ok);
		if(debug_check_ok && this->queue.size()) {
			cout << endl;
		}
		if(debug_rslt) {
			cout << " -- RSLT: ";
			if(rslt_check_ok <= 0) {
				if(!this->queue.size()) {
					cout << "EMPTY";
				} else {
					cout << "ERRRRRRRRRRRRRRRROOOOOORRRRRRRRRR";
					if(this->rst) {
						cout << " - RST";
					}
				}
			} else {
				cout << "OK";
			}
			cout << " " << this->port_src << " / " << this->port_dst;
			cout << endl;
		}
		if(rslt_check_ok > 0) {
			this->complete();
			this->state = STATE_CLOSED;
		}
	}
	return(rslt);
}
*/

bool TcpReassemblyLink::push_crazy(
			TcpReassemblyStream::eDirection direction,
			timeval time, tcphdr header_tcp, 
			u_char *data, u_int32_t datalen, u_int32_t datacaplen,
			pcap_block_store *block_store, int block_store_index,
			bool lockQueue) {
	/*if(!(datalen > 0 ||
	     header_tcp.syn || header_tcp.fin || header_tcp.rst)) {
		return(false);
	}*/
	direction = header_tcp.dest == this->port_dst ?
			TcpReassemblyStream::DIRECTION_TO_DEST :
			TcpReassemblyStream::DIRECTION_TO_SOURCE;
	if(this->direction_confirm < 2) {
		TcpReassemblyStream::eDirection checked_direction = direction;
		if(this->direction_confirm < 2 && header_tcp.syn) {
			if(header_tcp.ack) {
				checked_direction = TcpReassemblyStream::DIRECTION_TO_SOURCE;
			} else {
				checked_direction = TcpReassemblyStream::DIRECTION_TO_DEST;
			}
			this->direction_confirm = 2;
		}
		if(!this->direction_confirm &&
		   ((datalen > 5 && !memcmp(data, "POST ", 5)) ||
		    (datalen > 4 && !memcmp(data, "GET ", 4)) ||
		    (datalen > 5 && !memcmp(data, "HEAD ", 5)))) {
			checked_direction = TcpReassemblyStream::DIRECTION_TO_DEST;
			this->direction_confirm = 1;
		}
		if(checked_direction != direction) {
			direction = checked_direction;
			this->switchDirection(lockQueue);
		}
	}
	TcpReassemblyStream_packet packet;
	packet.setData(time, header_tcp,
		       data, datalen, datacaplen,
		       block_store, block_store_index);
	TcpReassemblyStream *stream;
	map<uint32_t, TcpReassemblyStream*>::iterator iter;
	if(lockQueue) {
		this->lock_queue();
	}
	for(int i = 0; i < 3; i++) {
		if(i == 0 ? datalen > 0 : 
		   i == 1 ? header_tcp.syn || header_tcp.fin || header_tcp.rst : 
			    datalen == 0 && !(header_tcp.syn || header_tcp.fin || header_tcp.rst)) {
			map<uint32_t, TcpReassemblyStream*> *queue = i == 0 ? &this->queue_by_ack : 
								     i == 1 ? &this->queue_flags_by_ack :
									      &this->queue_nul_by_ack;
			iter = queue->find(packet.header_tcp.ack_seq);
			if(iter == queue->end()) {
				stream = new TcpReassemblyStream(this);
				stream->direction = direction;
				stream->ack = packet.header_tcp.ack_seq;
				if(i == 1) {
					stream->type = header_tcp.syn ? (header_tcp.ack ? 
										TcpReassemblyStream::TYPE_SYN_RECV :
										TcpReassemblyStream::TYPE_SYN_SENT) :
						       header_tcp.fin ? TcpReassemblyStream::TYPE_FIN :
									TcpReassemblyStream::TYPE_RST;
				}
				(*queue)[stream->ack] = stream;
				if(header_tcp.rst) {
					this->rst = true;
				}
				if(header_tcp.fin) {
					if(direction == TcpReassemblyStream::DIRECTION_TO_DEST) {
						this->fin_to_dest = true;
					} else {
						this->fin_to_source = true;
					}
				}
			} else {
				stream = iter->second;
			}
			stream->push(packet);
			if(!stream->min_seq ||
			   packet.header_tcp.seq < stream->min_seq) {
				stream->min_seq = packet.header_tcp.seq;
			}
			if(packet.next_seq > stream->max_next_seq) {
				stream->max_next_seq = packet.next_seq;
			}
		}
	}
	if(lockQueue) {
		this->unlock_queue();
	}
	//this->last_packet_at = getTimeMS();
	this->last_packet_at_from_header = time.tv_sec * 1000 + time.tv_usec / 1000;
	if(!this->created_at_from_header) {
		this->created_at_from_header = this->last_packet_at_from_header;
	}
	if(!opt_tcpreassembly_thread &&
	   (this->rst || this->fin_to_dest || this->fin_to_source) &&
	   !this->link_is_ok) {
		bool _cout = false;
		if(this->exists_data) {
			int countDataStream = this->okQueue(false, debug_check_ok);
			if(countDataStream > 1) {
				this->complete(false, true, lockQueue);
				if(debug_rslt) {
					cout << "RSLT: OK (" << countDataStream << ")";
					_cout = true;
				}
				this->link_is_ok = 1;
				// - 1 - prošlo tímto
				// - 2 - není už co k vyřízení - zatím se nastavuje jen po complete all
			}
		}
		if(_cout) {
			if(debug_packet) {
				in_addr ip;
				ip.s_addr = this->ip_src;
				string ip_src = inet_ntoa(ip);
				ip.s_addr = this->ip_dst;
				string ip_dst = inet_ntoa(ip);
				cout << " / "
				     << ip_src << " / " << this->port_src
				     << " -> "
				     << ip_dst << " / " << this->port_dst;
			}
			cout << endl;
		}
	}
	return(true);
}

/*
void TcpReassemblyLink::pushpacket(TcpReassemblyStream::eDirection direction,
				   TcpReassemblyStream_packet packet) {
	TcpReassemblyStream *stream;
	map<uint32_t, TcpReassemblyStream*>::iterator iter;
	this->lock_queue();
	iter = this->queue_by_ack.find(packet.header_tcp.ack_seq);
	if(iter == this->queue_by_ack.end()) {
		TcpReassemblyStream *prevStreamByLastAck = NULL;
		if(this->queue.size()) {
			prevStreamByLastAck = this->queue_by_ack[this->last_ack];
		}
		stream = new TcpReassemblyStream(this);
		stream->direction = direction;
		stream->ack = packet.header_tcp.ack_seq;
		if(prevStreamByLastAck && direction == prevStreamByLastAck->direction) {
			prevStreamByLastAck->last_seq = packet.header_tcp.seq;
			stream->first_seq = prevStreamByLastAck->last_seq;
		} else {
			stream->first_seq = this->queue.size() ? 
						prevStreamByLastAck->ack : 
						(direction == TcpReassemblyStream::DIRECTION_TO_DEST ?
							this->first_seq_to_dest :
							this->first_seq_to_source);
			this->setLastSeq(direction == TcpReassemblyStream::DIRECTION_TO_DEST ?
						TcpReassemblyStream::DIRECTION_TO_SOURCE :
						TcpReassemblyStream::DIRECTION_TO_DEST,
					 packet.header_tcp.ack_seq);
		}
		this->queue_by_ack[stream->ack] = stream;
		this->queue.push_back(stream);
		if(debug_packet) {
			cout << " -- NEW STREAM (" << stream->ack << ")"
			     << " - first_seq: " << stream->first_seq
			     << endl;
		}
	} else {
		stream = iter->second;
	}
	stream->push(packet);
	if(!stream->min_seq ||
	   packet.header_tcp.seq < stream->min_seq) {
		stream->min_seq = packet.header_tcp.seq;
	}
	if(packet.next_seq > stream->max_next_seq) {
		stream->max_next_seq = packet.next_seq;
	}
	this->last_ack = stream->ack;
	this->unlock_queue();
	this->last_packet_at = getTimeMS();
}
*/

void TcpReassemblyLink::printContent(int level) {
	map<uint32_t, TcpReassemblyStream*>::iterator iter;
	int counter = 0;
	for(iter = this->queue_by_ack.begin(); iter != this->queue_by_ack.end(); iter++) {
		in_addr ip;
		ip.s_addr = this->ip_src;
		string ip_src = inet_ntoa(ip);
		ip.s_addr = this->ip_dst;
		string ip_dst = inet_ntoa(ip);
		cout << fixed 
		     << setw(level * 5) << ""
		     << setw(3) << (++counter) << "   " 
		     << setw(15) << ip_src << "/" << setw(6) << this->port_src
		     << " -> " 
		     << setw(15) << ip_dst << "/" << setw(6) << this->port_dst
		     << endl;
		iter->second->printContent(level + 1);
	}
}

void TcpReassemblyLink::cleanup(u_int64_t act_time) {
	map<uint32_t, TcpReassemblyStream*>::iterator iter;
	for(iter = this->queue_by_ack.begin(); iter != this->queue_by_ack.end(); ) {
		if(iter->second->queue.size() > 1000) {
			if(this->reassembly->isActiveLog()) {
				in_addr ip;
				ip.s_addr = this->ip_src;
				string ip_src = inet_ntoa(ip);
				ip.s_addr = this->ip_dst;
				string ip_dst = inet_ntoa(ip);
				ostringstream outStr;
				outStr << fixed 
				       << "cleanup - remove ack " << iter->first 
				       << " (too much seq - " << iter->second->queue.size() << ") "
				       << setw(15) << ip_src << "/" << setw(6) << this->port_src
				       << " -> " 
				       << setw(15) << ip_dst << "/" << setw(6) << this->port_dst;
				this->reassembly->addLog(outStr.str().c_str());
			}
			delete iter->second;
			this->queue_by_ack.erase(iter++);
		} else {
			++iter;
		}
	}
}

void TcpReassemblyLink::setLastSeq(TcpReassemblyStream::eDirection direction, 
				   u_int32_t lastSeq) {
	int index = this->queue.size();
	if(index > 0 && this->queue[index - 1]->direction == direction) {
		index = index - 1;
	} else if(index > 1 && this->queue[index - 2]->direction == direction) { 
		index = index - 2;
	} else {
		return;
	}
	this->queue[index]->last_seq = lastSeq;
	if(debug_packet) {
		cout << " -- set last seq: " << lastSeq << endl; 
	}
}

/*
int TcpReassemblyLink::okQueue_normal(bool final, bool enableDebug) {
	bool rslt;
	size_t size = this->queue.size();
	for(size_t i = 0; i < size; i++) {
		if(enableDebug) {
			cout << "|";
		}
		rslt = this->queue[i]->ok(false, i == size - 1 && (this->rst || this->fin_to_dest || this->fin_to_source), 0,
					  false, NULL, enableDebug);
		if(rslt <= 0) {
			return(rslt);
		}
	}
	return(rslt);
}
*/

int TcpReassemblyLink::okQueue_crazy(bool final, bool enableDebug) {
	streamIterator iter = this->createIterator();
	if(!this->direction_confirm) {
		return(-2);
	}
	if(!iter.stream) {
		return(-10);
	}
	this->ok_streams.clear();
	int countDataStream = 0;
	for(int pass = 0; pass < (final ? /*3*/2 : 1) && !countDataStream; pass++) {
		vector<u_int32_t> processedAck;
		if(pass > 0) {
			iter.init();
		}
		TcpReassemblyStream *lastHttpStream = NULL;
		while(true) {
			if(pass == 1 &&
			   iter.state == STATE_SYN_FORCE_OK) {
				if(!iter.nextAckInDirection()) {
					break;
				}
			}
			
			/*
			if(iter.stream->ack == 3500116174) {
				cout << " -- ***** -- ";
			}
			*/
			
			if(enableDebug && debug_check_ok_process) {
				iter.print();
				cout << "   ";
			}
			if(iter.state >= STATE_SYN_OK) {
				processedAck.push_back(iter.stream->ack);
				u_int32_t maxNextSeq = iter.getMaxNextSeq();
				if((maxNextSeq || true/*pass == 2*/) &&
				   iter.stream->exists_data) {
					if(enableDebug) {
						cout << "|";
					}
					if(iter.stream->ok(true, maxNextSeq == 0, maxNextSeq,
							   true/*pass == 2*/, lastHttpStream, enableDebug)) {
						bool existsAckInStream = false;
						for(size_t i  = 0; i < this->ok_streams.size(); i++) {
							if(this->ok_streams[i]->ack == iter.stream->ack) {
								existsAckInStream = true;
								break;
							}
						}
						if(!existsAckInStream) {
							this->ok_streams.push_back(iter.stream);
							++countDataStream;
							if(iter.stream->http_ok) {
								lastHttpStream = iter.stream;
							}
						}
					} else if(pass == /*2*/1) {
						if(iter.nextSeqInDirection()) {
							continue;
						}
					}
				}
			}
			
			/*
			if(iter.stream->ack == 3805588303) {
				cout << " -- ***** -- ";
			}
			*/
			
			if(enableDebug && debug_check_ok_process) {
				cout << endl;
			}
			if(!iter.next()) {
				bool completeExpectContinue = false;
				if(iter.stream->direction == TcpReassemblyStream::DIRECTION_TO_SOURCE &&
				   iter.stream->complete_data.getData() &&
				   iter.stream->complete_data.getDatalen() == 25 &&
				   !memcmp(iter.stream->complete_data.getData(), "HTTP/1.1 100 Continue\r\n\r\n", 25) &&
				   this->ok_streams.size() > 1 &&
				   this->ok_streams[this->ok_streams.size() - 2]->http_expect_continue &&
				   this->ok_streams[this->ok_streams.size() - 2]->http_content_length &&
				   iter.stream->ack > this->ok_streams[this->ok_streams.size() - 2]->min_seq &&
				   iter.stream->ack < this->ok_streams[this->ok_streams.size() - 2]->max_next_seq) {
					TcpReassemblyDataItem dataItem = this->ok_streams[this->ok_streams.size() - 2]->complete_data;
					this->ok_streams[this->ok_streams.size() - 2]->complete_data.clearData();
					this->ok_streams[this->ok_streams.size() - 2]->is_ok = false;
					this->ok_streams[this->ok_streams.size() - 2]->_ignore_expect_continue = true;
					if(this->ok_streams[this->ok_streams.size() - 2]->ok(true, false, 0,
											     true, NULL, false)) {
						completeExpectContinue = true;
						iter.stream = this->ok_streams[this->ok_streams.size() - 2];
						if(!iter.nextAckInDirection()) {
							break;
						}
					}
					if(!completeExpectContinue &&
					   this->ok_streams[this->ok_streams.size() - 2]->detect_ok_max_next_seq) {
						if(this->ok_streams[this->ok_streams.size() - 2]->ok2_ec(iter.stream->max_next_seq)) {
							this->ok_streams.push_back(this->queue_by_ack[iter.stream->max_next_seq]);
							completeExpectContinue = true;
							iter.stream = this->ok_streams[this->ok_streams.size() - 1];
							iter.next();
						}
					}
					if(!completeExpectContinue) {
						this->ok_streams[this->ok_streams.size() - 2]->is_ok = true;
						this->ok_streams[this->ok_streams.size() - 2]->_ignore_expect_continue = false;
						this->ok_streams[this->ok_streams.size() - 2]->complete_data = dataItem;
					}
				} else if(this->ok_streams.size() > 0 &&
					  this->ok_streams[this->ok_streams.size() - 1]->http_expect_continue &&
					  this->ok_streams[this->ok_streams.size() - 1]->complete_data.getData() && 
					  this->ok_streams[this->ok_streams.size() - 1]->complete_data.getDatalen() < this->ok_streams[this->ok_streams.size() - 1]->http_content_length) {
					TcpReassemblyDataItem dataItem = this->ok_streams[this->ok_streams.size() - 1]->complete_data;
					this->ok_streams[this->ok_streams.size() - 1]->complete_data.clearData();
					this->ok_streams[this->ok_streams.size() - 1]->is_ok = false;
					this->ok_streams[this->ok_streams.size() - 1]->_ignore_expect_continue = true;
					if(!this->ok_streams[this->ok_streams.size() - 1]->ok(true, false, 0,
											      true, NULL, false)) {
						this->ok_streams[this->ok_streams.size() - 1]->is_ok = true;
						this->ok_streams[this->ok_streams.size() - 1]->_ignore_expect_continue = false;
						this->ok_streams[this->ok_streams.size() - 1]->complete_data = dataItem;
					}
				}
				if(!completeExpectContinue) {
					if(iter.stream->direction == TcpReassemblyStream::DIRECTION_TO_DEST) {
						if(!iter.nextAckInDirection()) {
							break;
						}
					} else if(iter.stream->direction == TcpReassemblyStream::DIRECTION_TO_SOURCE) {
						if(!iter.nextAckInReverseDirection()) {
							break;
						}
					} else {
						break;
					}
					if(iter.stream && iter.stream->ack) {
						bool okAck = true;
						while(std::find(processedAck.begin(), processedAck.end(), iter.stream->ack) != processedAck.end()) {
							if(!iter.nextAckInDirection()) {
								okAck = false;
								break;
							}
						}
						if(!okAck) {
							break;
						}
					}
				}
			} else if(iter.stream->direction == TcpReassemblyStream::DIRECTION_TO_SOURCE &&
				  (!iter.stream->complete_data.getData() ||
				   iter.stream->complete_data.getDatalen() < 25 ||
				   memcmp(iter.stream->complete_data.getData(), "HTTP/1.1 100 Continue\r\n\r\n", 25))) {
				if(this->ok_streams.size() > 0 &&
				   this->ok_streams[this->ok_streams.size() - 1]->http_expect_continue &&
				   this->ok_streams[this->ok_streams.size() - 1]->complete_data.getData() &&
				   this->ok_streams[this->ok_streams.size() - 1]->complete_data.getDatalen() <
						this->ok_streams[this->ok_streams.size() - 1]->http_content_length + this->ok_streams[this->ok_streams.size() - 1]->http_header_length) {
					TcpReassemblyDataItem dataItem = this->ok_streams[this->ok_streams.size() - 1]->complete_data;
					this->ok_streams[this->ok_streams.size() - 1]->complete_data.clearData();
					this->ok_streams[this->ok_streams.size() - 1]->is_ok = false;
					this->ok_streams[this->ok_streams.size() - 1]->_ignore_expect_continue = true;
					if(!this->ok_streams[this->ok_streams.size() - 1]->ok(true, false, 0,
											      true, NULL, false)) {
						this->ok_streams[this->ok_streams.size() - 1]->is_ok = true;
						this->ok_streams[this->ok_streams.size() - 1]->_ignore_expect_continue = false;
						this->ok_streams[this->ok_streams.size() - 1]->complete_data = dataItem;
						this->ok_streams[this->ok_streams.size() - 1]->http_expect_continue = true;
					}
				}
			}
		}
	}
	return(iter.state < STATE_SYN_OK ? -1 : countDataStream);
}

/*
void TcpReassemblyLink::complete_normal() {
	this->lock_queue();
	size_t size = this->queue.size();
	while(true) {
		size_t countRequest = 0;
		size_t countRslt = 0;
		bool ok = true;
		while(this->completed_offset + countRequest < size && 
		      this->queue[this->completed_offset + countRequest]->direction == TcpReassemblyStream::DIRECTION_TO_DEST) {
			if(!this->queue[this->completed_offset + countRequest]->ok()) {
				ok = false;
				break;
			}
			++countRequest;
		}
		if(!countRequest || !ok) {
			break;
		}
		while(this->completed_offset + countRequest + countRslt < size && 
		      this->queue[this->completed_offset + countRequest + countRslt]->direction == TcpReassemblyStream::DIRECTION_TO_SOURCE) {
			if(!this->queue[this->completed_offset + countRequest + countRslt]->ok()) {
				ok = false;
				break;
			}
			++countRslt;
		}
		if(!countRslt || !ok) {
			break;
		}
		for(size_t i = 0; i < countRequest + countRslt; i++) {
			TcpReassemblyStream *stream = this->queue[this->completed_offset + i];
			u_char *data;
			u_int32_t datalen;
			timeval time;
			data = stream->complete(&datalen, &time);
			if(data) {
				if(debug_data) {
					cout << endl;
					if(i == 0) {
						cout << "** REQUEST **" << endl << endl;
					} else if (i == countRequest) {
						cout << "** RSLT **" << endl << endl;
					}
					cout << data << endl << endl;
				}
				delete [] data;
			}
		}
		this->completed_offset += countRequest + countRslt;
	}
	this->unlock_queue();
}
*/

void TcpReassemblyLink::complete_crazy(bool final, bool eraseCompletedStreams, bool lockQueue) {
	if(lockQueue) {
		this->lock_queue();
	}
	while(true) {
		size_t size_ok_streams = this->ok_streams.size();
		TcpReassemblyData *reassemblyData = NULL;
		size_t skip_offset = 0;
		while(skip_offset < size_ok_streams && 
		      this->ok_streams[skip_offset]->direction != TcpReassemblyStream::DIRECTION_TO_DEST) {
			this->ok_streams[skip_offset + completed_offset]->completed_finally = true;
			++skip_offset;
		}
		size_t old_skip_offset;
		do {
			old_skip_offset = skip_offset;
			while(skip_offset < size_ok_streams && this->ok_streams[skip_offset + completed_offset]->completed_finally) {
				++skip_offset;
			}
			while(skip_offset < size_ok_streams && 
			      this->ok_streams[skip_offset]->direction != TcpReassemblyStream::DIRECTION_TO_DEST) {
				this->ok_streams[skip_offset + completed_offset]->completed_finally = true;
				++skip_offset;
			}
			while(skip_offset < size_ok_streams && 
			      !this->ok_streams[skip_offset]->http_type) {
				this->ok_streams[skip_offset + completed_offset]->completed_finally = true;
				++skip_offset;
			}
		} while(skip_offset > old_skip_offset);
		size_t countRequest = 0;
		size_t countRslt = 0;
		bool postExpectContinueInFirstRequest = false;
		bool forceExpectContinue = false;
		while(skip_offset + countRequest < size_ok_streams && 
		      this->ok_streams[skip_offset + countRequest]->direction == TcpReassemblyStream::DIRECTION_TO_DEST) {
			
			/*
			if(this->ok_streams[skip_offset + countRequest]->ack == 3805588303) {
				cout << "-- ***** --" << endl;
			}
			*/
			
			++countRequest;
			if(countRequest == 1) {
				u_char *data = this->ok_streams[skip_offset]->complete_data.getData();
				u_int32_t datalen = this->ok_streams[skip_offset]->complete_data.getDatalen();
				if(!this->ok_streams[skip_offset]->http_ok_data_complete &&
				   data && datalen > 24 && 
				   !memcmp(data, "POST ", 5) &&
				   strcasestr((char*)data, "Expect: 100-continue")) {
					postExpectContinueInFirstRequest = true;
				} else {
					break;
				}
			}
			if(countRequest == 2 && postExpectContinueInFirstRequest) {
				u_char *data = this->ok_streams[skip_offset + 1]->complete_data.getData();
				u_int32_t datalen = this->ok_streams[skip_offset + 1]->complete_data.getDatalen();
				if(data && datalen > 0 && data[0] == '{') {
					forceExpectContinue = true;
					break;
				} else {
					--countRequest;
					break;
				}
			}
		}
		if(!countRequest) {
			break;
		}
		while(skip_offset + countRequest + countRslt < size_ok_streams && 
		      this->ok_streams[skip_offset + countRequest + countRslt]->direction == TcpReassemblyStream::DIRECTION_TO_SOURCE) {
			++countRslt;
		}
		if(postExpectContinueInFirstRequest && !forceExpectContinue) {
			if(final || skip_offset + countRequest + countRslt + 2 <= size_ok_streams) {
				// OK
			} else {
				break;
			}
		} else {
			if(final || countRslt) {
				// OK
			} else {
				break;
			}
		}
		reassemblyData = new TcpReassemblyData;
		bool existsSeparateExpectContinueData = false;
		for(size_t i = 0; i < countRequest + countRslt; i++) {
			TcpReassemblyStream *stream = this->ok_streams[skip_offset + i];
			u_char *data = stream->complete_data.getData();
			u_int32_t datalen = stream->complete_data.getDatalen();
			timeval time = stream->complete_data.getTime();
			if(data) {
				
				/*
				if(this->ok_streams[skip_offset + i]->ack == 2857364427) {
					cout << "-- ***** --" << endl;
				}
				*/
				
				if(i == countRequest - 1 &&
				   datalen > 24 && 
				   !memcmp(data, "POST ", 5) &&
				   strcasestr((char*)data, "Expect: 100-continue")) {
					if(skip_offset + countRequest + countRslt + 1 <= size_ok_streams) {
						if(this->ok_streams[skip_offset + countRequest + countRslt]->http_ok_expect_continue_data) {
							existsSeparateExpectContinueData = true;
							reassemblyData->forceAppendExpectContinue = true;
						} else if(this->ok_streams[skip_offset + countRequest + countRslt]->complete_data.getData() &&
							  this->ok_streams[skip_offset + countRequest + countRslt]->complete_data.getData()[0] == '{') {
							existsSeparateExpectContinueData = true;
						} else if(this->ok_streams[skip_offset]->http_header_length &&
							  this->ok_streams[skip_offset]->http_content_length &&
						          this->ok_streams[skip_offset + countRequest + countRslt]->complete_data.getData() &&
						          this->ok_streams[skip_offset]->complete_data.getDatalen() + 
									this->ok_streams[skip_offset + countRequest + countRslt]->complete_data.getDatalen() ==
								this->ok_streams[skip_offset]->http_header_length + this->ok_streams[skip_offset]->http_content_length + 4) {
							existsSeparateExpectContinueData = true;
							reassemblyData->forceAppendExpectContinue = true;
						}
					}
				}
				if(debug_data) {
					cout << endl;
					if(i == 0) {
						cout << "** REQUEST **";
					} else if (i == countRequest) {
						cout << "** RSLT **";
					}
					if(i == 0 || i == countRequest) {
						cout << endl << endl;
					}
					cout << "  ack: " << this->ok_streams[skip_offset + i]->ack << endl << endl;
					cout << data << endl << endl;
				}
				if(i < countRequest) {
					reassemblyData->addRequest(data, datalen, time);
				} else {
					reassemblyData->addResponse(data, datalen, time);
				}
				this->ok_streams[skip_offset + i]->completed_finally = true;
			}
		}
		if(existsSeparateExpectContinueData &&
		   skip_offset + countRequest + countRslt + 1 <= size_ok_streams && 
		   this->ok_streams[skip_offset + countRequest + countRslt]->direction == TcpReassemblyStream::DIRECTION_TO_DEST) {
			/*
			if(!ENABLE_UNLOCK_PACKET_IN_OK &&
			   countRequest == 1 && this->ok_streams[skip_offset]->http_ok &&
			   this->ok_streams[skip_offset]->http_expect_continue &&
			   this->ok_streams[skip_offset]->http_content_length &&
			   (dataItem.datalen > this->ok_streams[skip_offset]->http_content_length + 1 ||
			    dataItem.datalen < this->ok_streams[skip_offset]->http_content_length -1)) {
				this->ok_streams[skip_offset + countRequest + countRslt]->is_ok = false;
				this->ok_streams[skip_offset + countRequest + countRslt]->complete_data = NULL;
				if(this->ok_streams[skip_offset + countRequest + countRslt]->ok(true, false, 0,
												true, this->ok_streams[skip_offset], false)) {
					cout << "-- REPAIR STREAM --" << endl;
					dataItem.destroy();
					dataItem = this->ok_streams[skip_offset + countRequest + countRslt]->getCompleteData(true);
				}
			}
			*/
			u_char *data = this->ok_streams[skip_offset + countRequest + countRslt]->complete_data.getData();
			u_int32_t datalen = this->ok_streams[skip_offset + countRequest + countRslt]->complete_data.getDatalen();
			timeval time = this->ok_streams[skip_offset + countRequest + countRslt]->complete_data.getTime();
			if(data) {
				if(debug_data) {
					cout << endl;
					cout << "** EXPECT CONTINUE **";
					cout << endl << endl;
					cout << "  ack: " << this->ok_streams[skip_offset + countRequest + countRslt]->ack << endl << endl;
					cout << data << endl << endl;
				}
				reassemblyData->addExpectContinue(data, datalen, time);
				this->ok_streams[skip_offset + countRequest + countRslt]->completed_finally = true;
			}
			if(skip_offset + countRequest + countRslt + 2 <= size_ok_streams && 
			   this->ok_streams[skip_offset + countRequest + countRslt + 1]->direction == TcpReassemblyStream::DIRECTION_TO_SOURCE) {
				data = this->ok_streams[skip_offset + countRequest + countRslt + 1]->complete_data.getData();
				datalen = this->ok_streams[skip_offset + countRequest + countRslt + 1]->complete_data.getDatalen();
				time = this->ok_streams[skip_offset + countRequest + countRslt + 1]->complete_data.getTime();
				if(debug_data) {
					cout << endl;
					cout << "** EXPECT CONTINUE RSLT **";
					cout << endl << endl;
					cout << "  ack: " << this->ok_streams[skip_offset + countRequest + countRslt + 1]->ack << endl << endl;
					cout << data << endl << endl;
				}
				reassemblyData->addExpectContinueResponse(data, datalen, time);
				this->ok_streams[skip_offset + countRequest + countRslt + 1]->completed_finally = true;
			}
		}
		if(reassemblyData->isFill()) {
			if(reassembly->dataCallback) {
				reassembly->dataCallback->processData(
					this->ip_src, this->ip_dst,
					this->port_src, this->port_dst,
					reassemblyData,
					debug_save);
				reassemblyData = NULL;
			}
			if(eraseCompletedStreams) {
				while(this->ok_streams.size() && this->ok_streams[0]->completed_finally) {
					this->ok_streams[0]->is_ok = false;
					this->ok_streams[0]->completed = false;
					this->ok_streams.erase(this->ok_streams.begin());
				}
			}
			skip_offset = 0;
		}
		if(reassemblyData) {
			delete reassemblyData;
		}
	}
	if(lockQueue) {
		this->unlock_queue();
	}
}

TcpReassemblyLink::streamIterator TcpReassemblyLink::createIterator() {
	streamIterator iterator(this);
	return(iterator);
}

void TcpReassemblyLink::switchDirection(bool lockQueue) {
	if(lockQueue) {
		this->lock_queue();
	}
	u_int32_t tmp = this->ip_src;
	this->ip_src = this->ip_dst;
	this->ip_dst = tmp;
	tmp = this->port_src;
	this->port_src = this->port_dst;
	this->port_dst = tmp;
	tmp = this->fin_to_source;
	this->fin_to_source = this->fin_to_dest;
	this->fin_to_dest = tmp;
	map<uint32_t, TcpReassemblyStream*>::iterator iter;
	for(iter = this->queue_by_ack.begin(); iter != this->queue_by_ack.end(); iter++) {
		iter->second->direction = iter->second->direction == TcpReassemblyStream::DIRECTION_TO_DEST ?
						TcpReassemblyStream::DIRECTION_TO_SOURCE :
						TcpReassemblyStream::DIRECTION_TO_DEST;
	}
	for(iter = this->queue_flags_by_ack.begin(); iter != this->queue_flags_by_ack.end(); iter++) {
		iter->second->direction = iter->second->direction == TcpReassemblyStream::DIRECTION_TO_DEST ?
						TcpReassemblyStream::DIRECTION_TO_SOURCE :
						TcpReassemblyStream::DIRECTION_TO_DEST;
	}
	for(iter = this->queue_nul_by_ack.begin(); iter != this->queue_nul_by_ack.end(); iter++) {
		iter->second->direction = iter->second->direction == TcpReassemblyStream::DIRECTION_TO_DEST ?
						TcpReassemblyStream::DIRECTION_TO_SOURCE :
						TcpReassemblyStream::DIRECTION_TO_DEST;
	}
	if(lockQueue) {
		this->unlock_queue();;
	}
}


TcpReassembly::TcpReassembly() {
	this->_sync_links = 0;
	this->enableHttpForceInit = false;
	this->enableCrazySequence = false;
	this->dataCallback = NULL;
	this->act_time_from_header = 0;
	this->last_time = 0;
	this->doPrintContent = false;
	this->threadHandle = 0;
	this->threadId = 0;
	this->terminated = false;
	this->ignoreTerminating = false;
	if(opt_tcpreassembly_thread) {
		this->createThread();
	}
	if(opt_tcpreassembly_log[0]) {
		this->log = fopen(opt_tcpreassembly_log, "at");
		if(this->log) {
			this->addLog((string(" -- start ") + sqlDateTimeString(getTimeMS()/1000)).c_str());
		}
	} else {
		this->log = NULL;
	}
}

TcpReassembly::~TcpReassembly() {
	if(!opt_tcpreassembly_thread || opt_pb_read_from_file[0]) {
		this->cleanup(true);
	}
	if(this->log) {
		this->addLog((string(" -- stop ") + sqlDateTimeString(getTimeMS()/1000)).c_str());
		fclose(this->log);
	}
}

inline void *_TcpReassembly_threadFunction(void* arg) {
	return(((TcpReassembly*)arg)->threadFunction(arg));
}

void TcpReassembly::createThread() {
	pthread_create(&this->threadHandle, NULL, _TcpReassembly_threadFunction, this);
}

void* TcpReassembly::threadFunction(void* ) {
	while(!terminating || this->ignoreTerminating) {
		for(int i = 0; i < 5 && (!terminating || this->ignoreTerminating); i++) {
			sleep(5);
		}
		if(!terminating || this->ignoreTerminating) {
			this->cleanup();
		}
	}
	return(NULL);
}

void TcpReassembly::setIgnoreTerminating(bool ignoreTerminating) {
	this->ignoreTerminating = ignoreTerminating;
}

void TcpReassembly::addLog(const char *logString) {
	if(!this->log) {
		return;
	}
	fputs(logString, this->log);
	fputc('\n', this->log);
	fflush(this->log);
}

void TcpReassembly::push(pcap_pkthdr *header, iphdr2 *header_ip, u_char *packet,
			 pcap_block_store *block_store, int block_store_index) {
	if(debug_limit_counter && debug_counter > debug_limit_counter) {
		return;
	}

	tcphdr *header_tcp_pointer;
	tcphdr header_tcp;
	u_char *data;
	u_int32_t datalen;
	u_int32_t datacaplen;
	
	header_tcp_pointer = (tcphdr*)((u_char*)header_ip + sizeof(*header_ip));
	data = (u_char*)header_tcp_pointer + (header_tcp_pointer->doff << 2);
	datalen = htons(header_ip->tot_len) - sizeof(*header_ip) - (header_tcp_pointer->doff << 2);
	datacaplen = header->caplen - ((u_char*)data - packet);
	header_tcp = *header_tcp_pointer;
	header_tcp.source = htons(header_tcp.source);
	header_tcp.dest = htons(header_tcp.dest);
	header_tcp.seq = htonl(header_tcp.seq);
	header_tcp.ack_seq = htonl(header_tcp.ack_seq);
	u_int32_t next_seq = header_tcp.seq + datalen;
	
	if(debug_port) {
		if(header_tcp.source != debug_port && header_tcp.dest != debug_port) {
			return;
		}
	}
	
	if(debug_seq && header_tcp.seq == debug_seq) {
		cout << " -- XXX DEBUG SEQ XXX" << endl;
	}

	this->last_time = getTimeMS();
	this->act_time_from_header = header->ts.tv_sec * 1000 + header->ts.tv_usec / 1000;
	
	TcpReassemblyLink *link = NULL;
	map<TcpReassemblyLink_id, TcpReassemblyLink*>::iterator iter;
	TcpReassemblyStream::eDirection direction = TcpReassemblyStream::DIRECTION_TO_DEST;
	TcpReassemblyLink_id id(header_ip->saddr, header_ip->daddr, header_tcp.source, header_tcp.dest);
	TcpReassemblyLink_id idr(header_ip->daddr, header_ip->saddr, header_tcp.dest, header_tcp.source);
	bool findLink = false;
	while(true) {
		this->lock_links();
		iter = this->links.find(id);
		if(iter != this->links.end()) {
			if(iter->second->_sync_queue == 0) {
				iter->second->lock_queue();
				findLink = true;
				break;
			}
		} else {
			iter = this->links.find(idr);
			if(iter != this->links.end()) {
				if(iter->second->_sync_queue == 0) {
					iter->second->lock_queue();
					direction = TcpReassemblyStream::DIRECTION_TO_SOURCE;
					findLink = true;
					break;
				}
			} else {
				break;
			}
		}
		this->unlock_links();
	}
	if(findLink) {
		link = iter->second;
		if(!this->enableCrazySequence &&
		   link->state == TcpReassemblyLink::STATE_SYN_SENT &&
		   this->enableHttpForceInit &&
		   direction == TcpReassemblyStream::DIRECTION_TO_DEST &&
		   ((datalen > 5 && !memcmp(data, "POST ", 5)) ||
		    (datalen > 4 && !memcmp(data, "GET ", 4)))) {
			link->state = TcpReassemblyLink::STATE_SYN_FORCE_OK;
		}
	} else {
		if(!this->enableCrazySequence &&
		   header_tcp.syn && !header_tcp.ack) {
			link = new TcpReassemblyLink(this, header_ip->saddr, header_ip->daddr, header_tcp.source, header_tcp.dest);
			link->lock_queue();
			this->links[id] = link;
		} else if(this->enableCrazySequence ||
			  (this->enableHttpForceInit &&
			   ((datalen > 5 && !memcmp(data, "POST ", 5)) ||
			    (datalen > 4 && !memcmp(data, "GET ", 4))))) {
			link = new TcpReassemblyLink(this, header_ip->saddr, header_ip->daddr, header_tcp.source, header_tcp.dest);
			link->lock_queue();
			this->links[id] = link;
			if(this->enableCrazySequence) {
				link->state = TcpReassemblyLink::STATE_CRAZY;
			} else {
				link->state = TcpReassemblyLink::STATE_SYN_FORCE_OK;
				link->first_seq_to_dest = header_tcp.seq;
			}
		}
	}
	if(link) {
		link->push(direction, header->ts, header_tcp, 
			   data, datalen, datacaplen,
			   block_store, block_store_index,
			   false);
		link->unlock_queue();
	}
	this->unlock_links();

	if(debug_packet) {
		in_addr ip;
		ip.s_addr = header_ip->saddr;
		string ip_src = inet_ntoa(ip);
		ip.s_addr = header_ip->daddr;
		string ip_dst = inet_ntoa(ip);
		string _data;
		if(datalen) {
			char *__data = new char[datalen + 1];
			memcpy(__data, data, datalen);
			__data[datalen] = 0;
			_data = __data;
			delete [] __data;
			_data = _data.substr(0, 1000);
			for(size_t i = 0; i < _data.length(); i++) {
				if(_data[i] == 13 || _data[i] == 10) {
					_data[i] = '\\';
				}
				if(_data[i] < 32) {
					_data.resize(i);
				}
			}
		}
		cout << fixed
		     << sqlDateTimeString(header->ts.tv_sec) << "." << setw(6) << header->ts.tv_usec
		     << " : "
		     << setw(15) << ip_src << "/" << setw(6) << header_tcp.source
		     << " -> " 
		     << setw(15) << ip_dst << "/" << setw(6) << header_tcp.dest
		     << "   "
		     << (header_tcp.fin ? 'F' : '-')
		     << (header_tcp.syn ? 'S' : '-') 
		     << (header_tcp.rst ? 'R' : '-')
		     << (header_tcp.psh ? 'P' : '-')
		     << (header_tcp.ack ? 'A' : '-')
		     << (header_tcp.urg ? 'U' : '-')
		     << "  "
		     << " len: " << setw(5) << datalen
		     << " seq: " << setw(12) << header_tcp.seq
		     << " next seq: " << setw(12) << next_seq
		     << " ack: " << setw(12) << header_tcp.ack_seq
		     << " data: " << _data
		     << endl;
		++debug_counter;
		
		/*
		if(strstr((char*)data, "CHANNEL_CREATE")) {
			cout << "-- ***** --" << endl;
		}
		*/
		
	}

	if(!opt_tcpreassembly_thread) {
		static u_int32_t _counter;
		if(!((_counter++) % 100)) {
			this->cleanup();
		}
	}
}

void TcpReassembly::cleanup(bool all) {
	if(all) {
		cout << "cleanup all" << endl;
	}
	map<TcpReassemblyLink_id, TcpReassemblyLink*>::iterator iter;
	this->lock_links();
	if(all && opt_pb_read_from_file[0]) {
		cout << "COUNT REST LINKS: " << this->links.size() << endl;
	}
	for(iter = this->links.begin(); iter != this->links.end(); iter++) {
		iter->second->cleanup_state = 1;
	}
	this->unlock_links();
	
	u_int64_t act_time = this->act_time_from_header + getTimeMS() - this->last_time;
	
	while(true) {
		TcpReassemblyLink *link = NULL;
		this->lock_links();
		for(iter = this->links.begin(); iter != this->links.end(); iter++) {
			if(iter->second->cleanup_state == 1) {
				link = iter->second;
				link->lock_queue();
				iter->second->cleanup_state = 2;
				break;
			}
		}
		if(link && link->queue_by_ack.size() > 1000) {
			if(this->isActiveLog()) {
				in_addr ip;
				ip.s_addr = link->ip_src;
				string ip_src = inet_ntoa(ip);
				ip.s_addr = link->ip_dst;
				string ip_dst = inet_ntoa(ip);
				ostringstream outStr;
				outStr << fixed 
				       << "cleanup - remove link "
				       << "(too much ack - " << link->queue_by_ack.size() << ") "
				       << setw(15) << ip_src << "/" << setw(6) << link->port_src
				       << " -> "
				       << setw(15) << ip_dst << "/" << setw(6) << link->port_dst;
				this->addLog(outStr.str().c_str());
			}
			link->unlock_queue();
			delete link;
			this->links.erase(iter);
			this->unlock_links();
			continue;
		}
		this->unlock_links();
		if(!link) {
			break;
		}
		link->cleanup(act_time);
		bool final = act_time > link->last_packet_at_from_header + 2 * 60 * 1000;
		if((all || final ||
		    (link->last_packet_at_from_header &&
		     act_time > link->last_packet_at_from_header + 30 * 1000 &&
		     link->last_packet_at_from_header > link->last_packet_process_cleanup_at)) &&
		   (link->link_is_ok < 2 || opt_tcpreassembly_thread)) {
		 
			/*
			if(link->port_src == 53442 || link->port_dst == 53442) {
				cout << " -- ***** -- ";
			}
			*/
		 
			link->last_packet_process_cleanup_at = link->last_packet_at_from_header;
			bool _cout = false;
			if(!link->exists_data) {
				if(debug_rslt) {
					cout << "RSLT: EMPTY";
					_cout = true;
				}
			} else {
				int countDataStream = link->okQueue(true, debug_check_ok);
				if(countDataStream > 0) {
					link->complete(all || final, true, false);
					link->link_is_ok = 2;
				}
				if(debug_rslt) {
					if(countDataStream < 0) {
						cout << (countDataStream == -1 ? "RSLT: MISSING REQUEST" :
							(countDataStream == -2 ? "RSLT: DIRECTION NOT CONFIRMED" :
										 "RSLT: EMPTY OR OTHER ERROR"));
					}
					else if(countDataStream > 1) {
						cout << "RSLT: OK (" << countDataStream << ")";
					} else if(countDataStream > 0) {
						cout << "RSLT: ONLY REQUEST (" << countDataStream << ")";
					} else {
						cout << "RSLT: ERRRRRRRROR";
					}
					_cout = true;
				}
			}
			if(_cout) {
				if(debug_packet) {
					in_addr ip;
					ip.s_addr = link->ip_src;
					string ip_src = inet_ntoa(ip);
					ip.s_addr = link->ip_dst;
					string ip_dst = inet_ntoa(ip);
					cout << " clean "
					     << ip_src << " / " << link->port_src
					     << " -> "
					     << ip_dst << " / " << link->port_dst;
				}
				cout << endl;
			}
		}
		if(all || final ||
		   !link->existsFinallyUncompletedDataStream()) {
			link->unlock_queue();
			this->lock_links();
			delete link;
			link = NULL;
			this->links.erase(iter);
			this->unlock_links();
		}
		if(link) {
			link->unlock_queue();
		}
	}
	
	if(this->doPrintContent) {
		if(debug_print_content) {
			this->printContent();
		}
		this->doPrintContent = false;
	}
}

/*
bool TcpReassembly::enableStop() {
	return(getTimeMS() - this->last_time > 20 * 1000);
}
*/

void TcpReassembly::printContent() {
	map<TcpReassemblyLink_id, TcpReassemblyLink*>::iterator iter;
	int counter = 0;
	for(iter = this->links.begin(); iter != this->links.end(); iter++) {
		cout << fixed << setw(3) << (++counter) << "   "
		     << endl;
		iter->second->printContent(1);
	}
}
