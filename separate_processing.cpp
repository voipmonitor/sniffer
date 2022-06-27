#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "calltable.h"
#include "rtp.h"
#include "separate_processing.h"


#if EXPERIMENTAL_SEPARATE_PROCESSSING


extern Calltable *calltable;


/*
TODO
 - otestovat hash queue
 - OK okamžité ukončení
 - OK přidat cleanup thread
 - OK přidat logování plného bufferu mezi read a write/processing
 - rozlišit sip / rtp na úrovni vkládání do packetbufferu
*/


cSeparateProcessing::cSeparateProcessing(eMainType mainType, eSideType sideType) {
	this->mainType = mainType;
	this->sideType = sideType;
	buff_queue_max_length = 10000;
	buff_queue = new FILE_LINE(0) rqueue_quick<void*>(buff_queue_max_length, 0, 0, NULL, true);
	readThreadHandle = 0;
	writeThreadHandle = 0;
	processThreadHandle = 0;
	fd_fifo = -1;
	usleep_us = 20;
	terminating = false;
}

cSeparateProcessing::~cSeparateProcessing() {
	if(buff_queue) {
		delete buff_queue;
	}
}

void cSeparateProcessing::start() {
	initThreads();
}

void cSeparateProcessing::stop() {
	terminating = true;
	if(readThreadHandle) {
		pthread_join(readThreadHandle, NULL);
		readThreadHandle = 0;
	}
	if(writeThreadHandle) {
		pthread_join(writeThreadHandle, NULL);
		writeThreadHandle = 0;
	}
	if(processThreadHandle) {
		pthread_join(processThreadHandle, NULL);
		processThreadHandle = 0;
	}
}

void cSeparateProcessing::sendRtpIpPort(const char *call_id, u_int64_t call_first_packet_time_us, unsigned long call_flags, 
					u_int64_t time_us, 
					sDataRtpIpPort *rtpIpPort) {
	unsigned call_id_length = strlen(call_id);
	sDataHeader dataHeader;
	dataHeader.version = SEPARATE_PROCESSING_VERSION;
	dataHeader.data_type = _rtp_ip_port;
	dataHeader.length = sizeof(sDataCall) + call_id_length + sizeof(*rtpIpPort);
	sDataCall dataCall;
	dataCall.first_packet_time_us = call_first_packet_time_us;
	dataCall.call_flags = call_flags;
	dataCall.time_us = time_us;
	dataCall.call_id_length = call_id_length;
	unsigned buffLength = sizeof(dataHeader)  + dataHeader.length;
	u_char *buff = new u_char[buffLength];
	unsigned offset = 0;
	memcpy(buff + offset, &dataHeader, sizeof(dataHeader));
	offset += sizeof(dataHeader);
	memcpy(buff + offset, &dataCall, sizeof(dataCall));
	offset += sizeof(dataCall);
	memcpy(buff + offset, call_id, call_id_length);
	offset += call_id_length;
	memcpy(buff + offset, rtpIpPort, sizeof(*rtpIpPort));
	offset += sizeof(*rtpIpPort);
	pushBuff(buff);
}

void cSeparateProcessing::sendCloseCall(const char *call_id, u_int64_t call_first_packet_time_us, unsigned long call_flags,
					eCloseCallType type, u_int64_t time_us) {
	unsigned call_id_length = strlen(call_id);
	sDataHeader dataHeader;
	dataHeader.version = SEPARATE_PROCESSING_VERSION;
	dataHeader.data_type = _close_call;
	dataHeader.length = sizeof(sDataCloseCall) + call_id_length;
	sDataCloseCall dataCloseCall;
	dataCloseCall.first_packet_time_us = call_first_packet_time_us;
	dataCloseCall.call_flags = call_flags;
	dataCloseCall.type = type;
	dataCloseCall.time_us = time_us;
	dataCloseCall.call_id_length = call_id_length;
	unsigned buffLength = sizeof(dataHeader)  + dataHeader.length;
	u_char *buff = new u_char[buffLength];
	unsigned offset = 0;
	memcpy(buff + offset, &dataHeader, sizeof(dataHeader));
	offset += sizeof(dataHeader);
	memcpy(buff + offset, &dataCloseCall, sizeof(dataCloseCall));
	offset += sizeof(dataCloseCall);
	memcpy(buff + offset, call_id, call_id_length);
	offset += call_id_length;
	pushBuff(buff);
}

void cSeparateProcessing::sendRtpStreams(Call *call) {
	cSeparateProcessing::sDataRtpStream *streams = NULL;
	unsigned count_streams = call->ssrc_n;
	if(count_streams) {
		streams = new FILE_LINE(0) cSeparateProcessing::sDataRtpStream[count_streams];
		for(unsigned i = 0; i < count_streams; i++) {
			RTP *rtp = call->rtp_stream_by_index(i);
			memset((void*)&streams[i], 0, sizeof(cSeparateProcessing::sDataRtpStream));
			streams[i].saddr = rtp->saddr;
			streams[i].daddr = rtp->daddr;
			streams[i].sport = rtp->sport;
			streams[i].dport = rtp->dport;
			streams[i].ssrc = rtp->ssrc;
			streams[i].first_codec = rtp->first_codec_();
			streams[i].received = rtp->received_();
			streams[i].lost = rtp->lost_();
		}
	}
	cSeparateProcessing::sDataRtpTarPos *tar_pos = NULL;
	unsigned count_tar_pos = call->tarPosRtp.size();
	if(count_tar_pos) {
		tar_pos = new FILE_LINE(0) cSeparateProcessing::sDataRtpTarPos[count_tar_pos];
		unsigned i = 0;
		for(list<u_int64_t>::iterator iter = call->tarPosRtp.begin(); iter != call->tarPosRtp.end(); iter++) {
			tar_pos[i++].tar_pos = *iter;
			if(i == count_tar_pos) {
				break;
			}
		}
	}
	sendRtpStreams(call->call_id.c_str(), count_streams, streams, count_tar_pos, tar_pos);
	if(streams) {
		delete [] streams;
	}
	if(tar_pos) {
		delete [] tar_pos;
	}
}

void cSeparateProcessing::sendRtpStreams(const char *call_id, 
					 u_int32_t count_streams, sDataRtpStream streams[], 
					 u_int32_t count_tar_pos, sDataRtpTarPos tar_pos[]) {
	unsigned call_id_length = strlen(call_id);
	sDataHeader dataHeader;
	dataHeader.version = SEPARATE_PROCESSING_VERSION;
	dataHeader.data_type = _rtp_streams;
	dataHeader.length = sizeof(sDataRtpStream_header) + call_id_length + count_streams * sizeof(sDataRtpStream) + sizeof(sDataRtpTarPos_header) + count_tar_pos * sizeof(sDataRtpTarPos);
	sDataRtpStream_header dataRtpStream_header;
	dataRtpStream_header.count = count_streams;
	dataRtpStream_header.call_id_length = call_id_length;
	sDataRtpTarPos_header dataRtpTarPos_header;
	dataRtpTarPos_header.count = count_tar_pos;
	unsigned buffLength = sizeof(dataHeader)  + dataHeader.length;
	u_char *buff = new u_char[buffLength];
	unsigned offset = 0;
	memcpy(buff + offset, &dataHeader, sizeof(dataHeader));
	offset += sizeof(dataHeader);
	memcpy(buff + offset, &dataRtpStream_header, sizeof(dataRtpStream_header));
	offset += sizeof(dataRtpStream_header);
	memcpy(buff + offset, call_id, call_id_length);
	offset += call_id_length;
	for(unsigned i = 0; i < count_streams; i++) {
		memcpy(buff + offset, &streams[i], sizeof(streams[i]));
		offset += sizeof(streams[i]);
	}
	memcpy(buff + offset, &dataRtpTarPos_header, sizeof(dataRtpTarPos_header));
	offset += sizeof(dataRtpTarPos_header);
	for(unsigned i = 0; i < count_tar_pos; i++) {
		memcpy(buff + offset, &tar_pos[i], sizeof(tar_pos[i]));
		offset += sizeof(tar_pos[i]);
	}
	pushBuff(buff);
}

void cSeparateProcessing::sendRtpExists(Call *call) {
	sendRtpExists(call->call_id.c_str(), call->ssrc_n, call->first_rtp_time_us);
}

void cSeparateProcessing::sendRtpExists(const char *call_id, u_int32_t count_streams, u_int64_t first_rtp_time_us) {
	unsigned call_id_length = strlen(call_id);
	sDataHeader dataHeader;
	dataHeader.version = SEPARATE_PROCESSING_VERSION;
	dataHeader.data_type = _rtp_exists;
	dataHeader.length = sizeof(sDataRtpExists) + call_id_length;
	sDataRtpExists dataRtpExists;
	dataRtpExists.count_streams = count_streams;
	dataRtpExists.first_rtp_time_us = first_rtp_time_us;
	dataRtpExists.call_id_length = call_id_length;
	unsigned buffLength = sizeof(dataHeader)  + dataHeader.length;
	u_char *buff = new u_char[buffLength];
	unsigned offset = 0;
	memcpy(buff + offset, &dataHeader, sizeof(dataHeader));
	offset += sizeof(dataHeader);
	memcpy(buff + offset, &dataRtpExists, sizeof(dataRtpExists));
	offset += sizeof(dataRtpExists);
	memcpy(buff + offset, call_id, call_id_length);
	offset += call_id_length;
	pushBuff(buff);
}

void cSeparateProcessing::initThreads() {
	switch(mainType * 10 + sideType) {
	case _sip * 10 + _sender:
		startWriteThread();
		break;
	case _sip * 10 + _receiver:
		startReadThread();
		startProcessThread();
		break;
	case _rtp * 10 + _sender:
		startWriteThread();
		break;
	case _rtp * 10 + _receiver:
		startReadThread();
		startProcessThread();
		break;
	}
}

void cSeparateProcessing::startReadThread() {
	vm_pthread_create(("sep_proc - read thread  / " + getNameType()).c_str(),
			  &this->readThreadHandle, NULL, _readThread, this, __FILE__, __LINE__);
}

void cSeparateProcessing::startWriteThread() {
	vm_pthread_create(("sep_proc - write thread  / " + getNameType()).c_str(),
			  &this->writeThreadHandle, NULL, _writeThread, this, __FILE__, __LINE__);
}

void cSeparateProcessing::startProcessThread() {
	vm_pthread_create(("sep_proc - process thread  / " + getNameType()).c_str(),
			  &this->processThreadHandle, NULL, _processThread, this, __FILE__, __LINE__);
}

void *cSeparateProcessing::_readThread(void *arg) {
	((cSeparateProcessing*)arg)->readThread();
	return(NULL);
}

void *cSeparateProcessing::_writeThread(void *arg) {
	((cSeparateProcessing*)arg)->writeThread();
	return(NULL);
}

void *cSeparateProcessing::_processThread(void *arg) {
	((cSeparateProcessing*)arg)->processThread();
	return(NULL);
}

void cSeparateProcessing::readThread() {
	if(!openFifo()) {
		syslog(LOG_ERR, "%s: failed open fifo %s", getNameType().c_str(), getFifoPathName().c_str());
		// TODO
	} else {
		syslog(LOG_INFO, "%s: success open fifo %s", getNameType().c_str(), getFifoPathName().c_str());
	}
	while(!is_terminating()) {
		sDataHeader dataHeader;
		unsigned lengthHeader = sizeof(dataHeader);
		unsigned readBytes = 0;
		while(readBytes < lengthHeader && !is_terminating()) {
			int _readBytes = read(fd_fifo, ((u_char*)&dataHeader) + readBytes, lengthHeader - readBytes);
			if(_readBytes == -1) {
				// TODO
			} else {
				readBytes += _readBytes;
			}
		}
		if(is_terminating()) {
			break;
		}
		unsigned buffLength = sizeof(dataHeader)  + dataHeader.length;
		u_char *buff = new u_char[buffLength];
		memcpy(buff, &dataHeader, sizeof(dataHeader));
		unsigned offset = sizeof(dataHeader);
		readBytes = 0;
		while(readBytes < dataHeader.length && !is_terminating()) {
			int _readBytes = read(fd_fifo, buff + offset + readBytes, dataHeader.length - readBytes);
			if(_readBytes == -1) {
				// TODO
			} else {
				readBytes += _readBytes;
			}
		}
		/*{
		static int counter;
		cout << " *** buffer push " << hex << (void*)buff << dec << " " << (++counter) << endl;
		}*/
		buff_queue->push((void**)&buff, true);
	}
	closeFifo();
}

void cSeparateProcessing::writeThread() {
	if(!createFifo()) {
		syslog(LOG_ERR, "%s: failed create fifo %s", getNameType().c_str(), getFifoPathName().c_str());
		// TODO
	}
	if(!openFifo()) {
		syslog(LOG_ERR, "%s: failed open fifo %s", getNameType().c_str(), getFifoPathName().c_str());
		// TODO
	} else {
		syslog(LOG_INFO, "%s: success open fifo %s", getNameType().c_str(), getFifoPathName().c_str());
	}
	while(!is_terminating()) {
		void *buff;
		if(buff_queue->pop(&buff, false)) {
			unsigned lengthBuff = sizeof(sDataHeader) + ((sDataHeader*)buff)->length;
			unsigned writtedBytes = 0;
			while(writtedBytes < lengthBuff && !is_terminating()) {
				int _writtedBytes = write(fd_fifo, (u_char*)buff + writtedBytes, lengthBuff - writtedBytes);
				if(_writtedBytes == -1) {
					// TODO
				} else if(_writtedBytes > 0) {
					writtedBytes += _writtedBytes;
				}
			}
			delete [] (u_char*)buff;
		} else {
			usleep(usleep_us);
		}
	}
	closeFifo();
}

void cSeparateProcessing::processThread() {
	u_int64_t usleep_sum = 0;
	while(!is_terminating()) {
		void *buff;
		if(buff_queue->pop(&buff, false)) {
			usleep_sum = 0;
			/*{
			static int counter;
			cout << " *** buffer pop " << hex << (void*)buff << dec << " " << (++counter) << endl;
			}*/
			processBuff((u_char*)buff);
		} else {
			usleep(usleep_us);
			usleep_sum += usleep_us;
			if(usleep_sum > 100000) {
				if(processRtpIpPortData.data.size()) {
					processRtpIpPort(&processRtpIpPortData);
				}
				usleep_sum = 0;
			}
		}
	}
}

void cSeparateProcessing::pushBuff(u_char *buff) {
	if(!buff_queue->push((void**)&buff, false)) {
		static u_int32_t lastLog_at = 0;
		if(lastLog_at + 10 < getTimeS_rdtsc()) {
			syslog(LOG_INFO, "buff_queue is full in %s", getNameType().c_str());
			lastLog_at = getTimeS_rdtsc();
		}
		while(!is_terminating() && !buff_queue->push((void**)&buff, false));
	}
}

void cSeparateProcessing::processBuff(u_char *buff) {
	switch(((sDataHeader*)buff)->data_type) {
	case _rtp_ip_port:
		/*{
		static int counter;
		cout << " *** buffer rtp_ip_port " << hex << (void*)buff << dec << " " << (++counter) << endl;
		}*/
		processRtpIpPort(buff);
		break;
	case _close_call:
		/*{
		static int counter;
		cout << " *** buffer close " << hex << (void*)buff << dec << " " << (++counter) << endl;
		}*/
		processCloseCall(buff);
		break;
	case _rtp_streams:
		processRtpStreams(buff);
		break;
	case _rtp_exists:
		processRtpExists(buff);
		break;
	}
}

void cSeparateProcessing::processRtpIpPort(u_char *buff) {
	unsigned offset = sizeof(sDataHeader);
	sDataCall *dataCall = (sDataCall*)(buff + offset);
	offset += sizeof(sDataCall);
	string call_id = string((char*)(buff + offset), dataCall->call_id_length);
	offset += dataCall->call_id_length;
	sDataRtpIpPort *dataRtpIpPort = (sDataRtpIpPort*)(buff + offset);
	bool delete_buff = true;
	processRtpIpPort(call_id.c_str(), dataCall, dataRtpIpPort, buff, &delete_buff);
	if(delete_buff) {
		delete [] buff;
	}
}

void cSeparateProcessing::processRtpIpPort(const char *call_id, sDataCall *dataCall, sDataRtpIpPort *rtpIpPort, u_char *buff, bool *delete_buff) {
	if(sverb.separate_processing) {
		ostringstream str;
		str << "RTP IP PORT" << endl
		    << "callid: " << call_id << endl
		    << "first_packet_time_us: " << sqlDateTimeString_us2ms(dataCall->first_packet_time_us) << endl
		    << "time_us: " << sqlDateTimeString_us2ms(dataCall->time_us) << endl
		    << "add/del: " << (rtpIpPort->add ? "+++" : "---") << endl
		    << "ip: " << rtpIpPort->ip.getString() << endl
		    << "port: " << rtpIpPort->port.getString() << endl;
		cout << str.str();
	}
	if(!processRtpIpPortData.last_processed_time_us) {
		processRtpIpPortData.last_processed_time_us = dataCall->time_us;
	}
	sDataRtpIpPort_comb comb;
	comb.call_id = call_id;
	comb.callData = dataCall;
	comb.rtpIpPort = rtpIpPort;
	comb.buff = buff;
	processRtpIpPortData.data.push_back(comb);
	if(dataCall->time_us > processRtpIpPortData.last_processed_time_us &&
	   dataCall->time_us - processRtpIpPortData.last_processed_time_us > 100000) {
		processRtpIpPortData.last_processed_time_us = dataCall->time_us;
		processRtpIpPort(&processRtpIpPortData);
	}
	*delete_buff = false;
}

void cSeparateProcessing::processRtpIpPort(sProcessRtpIpPortData *data) {
	calltable->lock_calls_listMAP();
	map<string, Call*> callid_map;
	for(list<sDataRtpIpPort_comb>::iterator iter = data->data.begin(); iter != data->data.end(); iter++) {
		/*{
		static int counter;
		cout << " *** proc rtp " << hex << (void*)iter->buff << dec << " " << (++counter) << endl;
		}*/
		map<string, Call*>::iterator iter_callid_map = callid_map.find(iter->call_id);
		if(iter_callid_map != callid_map.end()) {
			iter->call = iter_callid_map->second;
			continue;
		}
		map<string, Call*>::iterator iter_calls_map = calltable->calls_listMAP.find(iter->call_id);
		Call *call;
		if(iter_calls_map != calltable->calls_listMAP.end()) {
			call = iter_calls_map->second;
		} else if(!iter->rtpIpPort->add) {
			iter->call = NULL;
			continue;
		} else {
			call = new FILE_LINE(0) Call(INVITE, (char*)iter->call_id.c_str(), iter->call_id.length(), NULL, iter->callData->first_packet_time_us);
			call->flags = iter->callData->call_flags;
			strcpy_null_term(call->fbasename, call->call_id.c_str());
			calltable->calls_listMAP[iter->call_id] = call;
		}
		callid_map[iter->call_id] = call;
		iter->call = call;
	}
	calltable->unlock_calls_listMAP();
	bool directModifyHash = false;
	if(directModifyHash) {
		calltable->lock_calls_hash();
	}
	for(list<sDataRtpIpPort_comb>::iterator iter = data->data.begin(); iter != data->data.end(); iter++) {
		if(iter->call && !iter->call->stopProcessing && !iter->call->sp_stop_rtp_processing_at) {
			if(iter->rtpIpPort->add) {
				if(directModifyHash) {
					calltable->_hashAddExt(iter->rtpIpPort->ip, iter->rtpIpPort->port, iter->callData->time_us, iter->call,
							       iter->rtpIpPort->is_caller, iter->rtpIpPort->is_rtcp, iter->rtpIpPort->sdp_flags, false);
				} else {
					calltable->hashAdd(iter->rtpIpPort->ip, iter->rtpIpPort->port, iter->callData->time_us, iter->call,
							   iter->rtpIpPort->is_caller, iter->rtpIpPort->is_rtcp, iter->rtpIpPort->sdp_flags);
				}
				iter->call->sp_rtp_ipport.insert(vmIPport(iter->rtpIpPort->ip, iter->rtpIpPort->port));
			} else {
				if(directModifyHash) {
					calltable->_hashRemoveExt(iter->call, iter->rtpIpPort->ip, iter->rtpIpPort->port, 
								  iter->rtpIpPort->is_rtcp, iter->rtpIpPort->ignore_rtcp_check);
				} else {
					calltable->hashRemove(iter->call, iter->rtpIpPort->ip, iter->rtpIpPort->port, 
							      iter->rtpIpPort->is_rtcp, iter->rtpIpPort->ignore_rtcp_check);
				}
			}
		}
		/*{
		static int counter;
		cout << " *** proc rtp - delete buff " << hex << (void*)iter->buff << dec << " " << (++counter) << endl;
		}*/
		delete [] iter->buff;
	}
	if(directModifyHash) {
		calltable->unlock_calls_hash();
	}
	data->data.clear();
}

void cSeparateProcessing::processCloseCall(u_char *buff) {
	unsigned offset = sizeof(sDataHeader);
	sDataCloseCall *dataCloseCall = (sDataCloseCall*)(buff + offset);
	offset += sizeof(sDataCloseCall);
	string call_id = string((char*)(buff + offset), dataCloseCall->call_id_length);
	processCloseCall(call_id.c_str(), dataCloseCall);
	delete [] buff;
}

void cSeparateProcessing::processCloseCall(const char *call_id, sDataCloseCall *dataCloseCall) {
	if(sverb.separate_processing) {
		ostringstream str;
		str << "CLOSE CALL" << endl
		    << "callid: " << call_id << endl
		    << "type: " << dataCloseCall->type << endl
		    << "time_us: " << sqlDateTimeString_us2ms(dataCloseCall->time_us) << endl;
		cout << str.str();
	}
	calltable->lock_calls_listMAP();
	map<string, Call*>::iterator iter_calls_map = calltable->calls_listMAP.find(call_id);
	Call *call;
	if(iter_calls_map != calltable->calls_listMAP.end()) {
		call = iter_calls_map->second;
	} else {
		call = new FILE_LINE(0) Call(INVITE, (char*)call_id, strlen(call_id), NULL, dataCloseCall->first_packet_time_us);
		call->flags = dataCloseCall->call_flags;
		strcpy_null_term(call->fbasename, call_id);
		calltable->calls_listMAP[call_id] = call;
	}
	if(dataCloseCall->type == _destroy_call_if_not_exists_rtp &&
	   (call->ssrc_n || call->first_rtp_time_us)) {
		calltable->unlock_calls_listMAP();
		sendExistsRtp(call);
		return;
	}
	call->sp_stop_rtp_processing_at = getTimeS_rdtsc();
	calltable->unlock_calls_listMAP();
	call->removeFindTables(true);
	if(dataCloseCall->type == _destroy_call || dataCloseCall->type == _destroy_call_if_not_exists_rtp) {
		call->sp_do_destroy_call_at = getTimeS_rdtsc();
	}
}

void cSeparateProcessing::processRtpStreams(u_char *buff) {
	unsigned offset = sizeof(sDataHeader);
	sDataRtpStream_header *dataRtpStream_header = (sDataRtpStream_header*)(buff + offset);
	offset += sizeof(sDataRtpStream_header);
	string call_id = string((char*)(buff + offset), dataRtpStream_header->call_id_length);
	offset += dataRtpStream_header->call_id_length;
	sDataRtpStream *streams = (sDataRtpStream*)(buff + offset);
	offset += dataRtpStream_header->count * sizeof(sDataRtpStream);
	sDataRtpTarPos_header *dataRtpTarPos_header = (sDataRtpTarPos_header*)(buff + offset);
	offset += sizeof(sDataRtpTarPos_header);
	sDataRtpTarPos *tar_pos = (sDataRtpTarPos*)(buff + offset);
	processRtpStreams(call_id.c_str(), dataRtpStream_header->count, streams, dataRtpTarPos_header->count, tar_pos);
	delete [] buff;
}

void cSeparateProcessing::processRtpStreams(const char *call_id, u_int32_t count_streams, sDataRtpStream streams[], u_int32_t count_tar_pos, sDataRtpTarPos tar_pos[]) {
	if(sverb.separate_processing) {
		ostringstream str;
		str << "RTP STREAMS" << endl
		    << "callid: " << call_id << endl
		    << "streams: " << count_streams << endl;
		if(count_streams) {
			for(unsigned i = 0; i < count_streams; i++) {
				str << (i+1) << " "
				    << streams[i].saddr.getString(true) << ":" << streams[i].sport.getString() << " -> "
				    << streams[i].daddr.getString(true) << ":" << streams[i].dport.getString() << ", "
				    << "r: " << streams[i].received << " l: " << streams[i].lost << endl;
			}
		}
		str << "tar_pos: "  << count_tar_pos;
		if(count_tar_pos) {
			str << " / ";
			for(unsigned i = 0; i < count_tar_pos; i++) {
				if(i) str << ",";
				str << tar_pos[i].tar_pos;
			}
		}
		str << endl;
		cout << str.str();
	}
	Call *call = NULL;
	calltable->lock_calls_listMAP();
	map<string, Call*>::iterator iter = calltable->calls_listMAP.find(call_id);
	if(iter != calltable->calls_listMAP.end()) {
		call = iter->second;
	}
	calltable->unlock_calls_listMAP();
	extern int preProcessPacketCallX_count;
	if(!call && preProcessPacketCallX_count > 0) {
		for(int i = 0; i < preProcessPacketCallX_count && !call; i++) {
			calltable->lock_calls_listMAP_X(i);
			map<string, Call*>::iterator iter = calltable->calls_listMAP_X[i].find(call_id);
			if(iter != calltable->calls_listMAP_X[i].end()) {
				call = iter->second;
			}
			calltable->unlock_calls_listMAP_X(i);
		}
	}
	if(call) {
		if(count_streams) {
			for(unsigned i = 0; i < count_streams; i++) {
				RTP *rtp;
				#if EXPERIMENTAL_LITE_RTP_MOD
				rtp = &call->rtp_fix[call->ssrc_n];
				#else
				rtp = new FILE_LINE(0) RTP;
				#endif
				rtp->saddr = streams[i].saddr;
				rtp->daddr = streams[i].daddr;
				rtp->sport = streams[i].sport;
				rtp->dport = streams[i].dport;
				rtp->ssrc = streams[i].ssrc;
				rtp->set_first_codec_(streams[i].first_codec);
				rtp->set_received_(streams[i].received);
				rtp->set_lost_(streams[i].lost);
				#if EXPERIMENTAL_LITE_RTP_MOD
				++call->ssrc_n;
				if(call->ssrc_n == MAX_SSRC_PER_CALL_FIX) {
					break;
				}
				#else
				add_rtp_stream(rtp);
				#endif
			}
		}
		if(count_tar_pos) {
			for(unsigned i = 0; i < count_tar_pos; i++) {
				call->tarPosRtp.push_back(tar_pos[i].tar_pos);
			}
		}
		call->sp_arrived_rtp_streams = true;
	}
}

void cSeparateProcessing::processRtpExists(u_char *buff) {
	unsigned offset = sizeof(sDataHeader);
	sDataRtpExists *dataRtpExists = (sDataRtpExists*)(buff + offset);
	offset += sizeof(sDataRtpExists);
	string call_id = string((char*)(buff + offset), dataRtpExists->call_id_length);
	processRtpExists(call_id.c_str(), dataRtpExists->count_streams, dataRtpExists->first_rtp_time_us);
	delete [] buff;
}

void cSeparateProcessing::processRtpExists(const char *call_id, u_int32_t count_streams, u_int64_t first_rtp_time_us) {
	if(sverb.separate_processing) {
		ostringstream str;
		str << "RTP EXISTS" << endl
		    << "callid: " << call_id << endl
		    << "streams: " << count_streams << endl;
		cout << str.str();
	}
	Call *call = NULL;
	calltable->lock_calls_listMAP();
	map<string, Call*>::iterator iter = calltable->calls_listMAP.find(call_id);
	if(iter != calltable->calls_listMAP.end()) {
		call = iter->second;
	}
	calltable->unlock_calls_listMAP();
	extern int preProcessPacketCallX_count;
	if(!call && preProcessPacketCallX_count > 0) {
		for(int i = 0; i < preProcessPacketCallX_count && !call; i++) {
			calltable->lock_calls_listMAP_X(i);
			map<string, Call*>::iterator iter = calltable->calls_listMAP_X[i].find(call_id);
			if(iter != calltable->calls_listMAP_X[i].end()) {
				call = iter->second;
			}
			calltable->unlock_calls_listMAP_X(i);
		}
	}
	if(call && !call->sp_do_destroy_call_at) {
		call->sp_sent_close_call = false;
		call->sipwithoutrtp_timeout_exceeded = false;
		call->zombie_timeout_exceeded = false;
		call->attemptsClose = 0;
		call->first_rtp_time_us = first_rtp_time_us ? first_rtp_time_us : (getTimeMS_rdtsc() * 1000);
		call->ssrc_n = count_streams;
	}
}

string cSeparateProcessing::getFifoPath() {
	return("/tmp");
}

string cSeparateProcessing::getFifoName() {
	switch(mainType * 10 + sideType) {
	case _sip * 10 + _sender:
	case _sip * 10 + _receiver:
		return("sniffer_sip_fifo");
		break;
	case _rtp * 10 + _sender:
	case _rtp * 10 + _receiver:
		return("sniffer_rtp_fifo");
		break;
	}
	return("");
}

string cSeparateProcessing::getFifoPathName() {
	return(getFifoPath() + "/" + getFifoName());
}

bool cSeparateProcessing::createFifo() {
	return(mkfifo(getFifoPathName().c_str(), 0666) == 0);
}

bool cSeparateProcessing::openFifo() {
	int fd = open(getFifoPathName().c_str(), sideType == _sender ? O_WRONLY : O_RDONLY);
	if(fd >= 0) {
		fd_fifo = fd;
		return(true);
	}
	return(false);
}

void cSeparateProcessing::closeFifo() {
	if(fd_fifo >= 0) {
		close(fd_fifo);
		fd_fifo = -1;
	}
}

bool cSeparateProcessing::is_terminating() {
	extern volatile int terminating;
	return(terminating || this->terminating);
}


static cSeparateProcessing *sip;
static cSeparateProcessing *rtp;


void separate_processing_init() {
	#if EXPERIMENTAL_SEPARATE_PROCESSSING
	if(separate_processing() == cSeparateProcessing::_sip) {
		sip = new FILE_LINE(0) cSeparateProcessing(cSeparateProcessing::_sip, cSeparateProcessing::_sender);
		rtp = new FILE_LINE(0) cSeparateProcessing(cSeparateProcessing::_rtp, cSeparateProcessing::_receiver);
	} else if(separate_processing() == cSeparateProcessing::_rtp) {
		sip = new FILE_LINE(0) cSeparateProcessing(cSeparateProcessing::_sip, cSeparateProcessing::_receiver);
		rtp = new FILE_LINE(0) cSeparateProcessing(cSeparateProcessing::_rtp, cSeparateProcessing::_sender);
	}
	#endif
}

void separate_processing_start() {
	#if EXPERIMENTAL_SEPARATE_PROCESSSING
	if(sip) {
		sip->start();
	}
	if(rtp) {
		rtp->start();
	}
	#endif
}

void separate_processing_stop() {
	#if EXPERIMENTAL_SEPARATE_PROCESSSING
	if(sip) {
		sip->stop();
	}
	if(rtp) {
		rtp->stop();
	}
	#endif
}

void separate_processing_term() {
	#if EXPERIMENTAL_SEPARATE_PROCESSSING
	if(sip) {
		delete sip;
		sip = NULL;
	}
	if(rtp) {
		delete rtp;
		rtp = NULL;
	}
	#endif
}

void sendRtpIpPort(const char *call_id, u_int64_t call_first_packet_time_us, unsigned long call_flags, 
		   u_int64_t time_us, 
		   cSeparateProcessing::sDataRtpIpPort *rtpIpPort) {
	if(sip) {
		sip->sendRtpIpPort(call_id, call_first_packet_time_us, call_flags,
				   time_us, 
				   rtpIpPort);
	}
}

void sendCloseCall(const char *call_id, u_int64_t call_first_packet_time_us, unsigned long call_flags,
		   cSeparateProcessing::eCloseCallType type, u_int64_t time_us) {
	if(sip) {
		sip->sendCloseCall(call_id, call_first_packet_time_us, call_flags, 
				   type, time_us);
	}
}

void sendRtpStreams(Call *call) {
	if(rtp) {
		rtp->sendRtpStreams(call);
	}
}

void sendExistsRtp(Call *call) {
	if(rtp) {
		rtp->sendRtpExists(call);
	}
}


#endif // EXPERIMENTAL_SEPARATE_PROCESSSING
