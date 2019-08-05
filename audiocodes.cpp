#include "audiocodes.h"


#define ACDR_VERSION_MAJOR	0
#define ACDR_VERSION_MINOR	9

#define HEADER_FIELD_VER_BYTE_NO			0
#define HEADER_FIELD_VER_BYTE_COUNT			1

#define HEADER_FIELD_TIME_BYTE_NO		 	1
#define HEADER_FIELD_OLD_TIME_BYTE_COUNT		6
#define HEADER_FIELD_NEW_TIME_BYTE_COUNT		4

#define HEADER_FIELD_SEQ_NUM_BYTE_NO			5
#define HEADER_FIELD_SEQ_NUM_BYTE_COUNT			2

#define HEADER_FIELD_SRC_ID_BYTE_NO			7
#define HEADER_FIELD_SRC_ID_BYTE_COUNT			id_length

#define HEADER_FIELD_DEST_ID_BYTE_NO			(HEADER_FIELD_SRC_ID_BYTE_NO + id_length)
#define HEADER_FIELD_DEST_ID_BYTE_COUNT			id_length

#define HEADER_FIELD_DATA_BYTE_NO			(HEADER_FIELD_DEST_ID_BYTE_NO + id_length)
#define HEADER_FIELD_DATA_BYTE_COUNT			1

#define HEADER_FIELD_TRACE_PT_BYTE_NO			(HEADER_FIELD_DATA_BYTE_NO + 1)
#define HEADER_FIELD_TRACE_PT_BYTE_COUNT		1

#define HEADER_FIELD_MEDIA_TYPE_BYTE_NO			(HEADER_FIELD_TRACE_PT_BYTE_NO + 1)
#define HEADER_FIELD_MEDIA_TYPE_BYTE_COUNT		1

#define HEADER_FIELD_PL_OFFSET_BYTE_NO			(HEADER_FIELD_MEDIA_TYPE_BYTE_NO + 1)
#define HEADER_FIELD_PL_OFFSET_BYTE_COUNT		1

#define HEADER_FIELD_HEADER_EXT_LEN_BYTE_NO		(HEADER_FIELD_MEDIA_TYPE_BYTE_NO + 1)
#define HEADER_FIELD_HEADER_EXT_LEN_BYTE_COUNT		1

#define HEADER_FIELD_SESSION_ID_BYTE_NO			(HEADER_FIELD_HEADER_EXT_LEN_BYTE_NO + 1)
#define HEADER_FIELD_SESSION_ID_BYTE_COUNT		4

#define HEADER_FIELD_FULL_SESSION_ID_BYTE_COUNT		8
#define HEADER_FIELD_LONG_FULL_SESSION_ID_BYTE_COUNT 	9

#define HEADER_FIELD_SESSION_ID_BOARD_ID_BYTE_NO	HEADER_FIELD_SESSION_ID_BYTE_NO
#define HEADER_FIELD_SESSION_ID_BOARD_ID_BYTE_COUNT	3

#define HEADER_FIELD_SESSION_ID_RESET_COUNT_BYTE_NO	(HEADER_FIELD_SESSION_ID_BOARD_ID_BYTE_NO + 3)
#define HEADER_FIELD_SESSION_ID_RESET_COUNT_BYTE_COUNT	1

#define HEADER_FIELD_SESSION_NUM_BYTE_NO		(HEADER_FIELD_SESSION_ID_RESET_COUNT_BYTE_NO + 1)
#define HEADER_FIELD_SESSION_NUM_BYTE_COUNT		4
#define HEADER_FIELD_LONG_SESSION_NUM_BYTE_COUNT 	5

#define MII_HEADER_BYTE_LENGTH				4

#define EXT_HEADER_IPV4_ADDRESS_BYTE_COUNT		4
#define EXT_HEADER_IPV6_ADDRESS_BYTE_COUNT		16
#define EXT_HEADER_UDP_PORT_BYTE_COUNT			2
#define EXT_HEADER_IP_TOS_BYTE_COUNT			1
#define EXT_HEADER_C5_CONTROL_FLAFS_COUNT		1

#define MEDIUM_MASK		0x1
#define IPV6_MASK		0x2
#define FRAGMENTED_MASK		0x4
#define HEADERADDED_MASK	0x8
#define ENCRYPTED_MASK		0x10
#define MTCE_MASK		0x20


void sAudiocodes::init() {
	#if __GNUC__ >= 8
	#pragma GCC diagnostic push
	#pragma GCC diagnostic ignored "-Wclass-memaccess"
	#endif
	memset(this, 0, sizeof(*this));
	#if __GNUC__ >= 8
	#pragma GCC diagnostic pop
	#endif
}

bool sAudiocodes::parse(u_char *ac_header, unsigned /*length*/) {
	init();
	u_int8_t id_length;
	bool medium_mii = false;
	bool header_added = false;
	u_int16_t t38_udp_port = 0;
	u_int16_t t38_udp_dest_port = 0;
	version = ac_header[HEADER_FIELD_VER_BYTE_NO];
	if(((version & 0xF) > ACDR_VERSION_MINOR) || (((version >> 4) & 0xF) != ACDR_VERSION_MAJOR)) {
		return(false);
        }
	if((version & 0xF) < 5) {
		header_length = 15;
		id_length = 2;
	} else if((version & 0xF) < 7) {
		header_length = 19;
		id_length = 2;
	} else if((version & 0xF) == 7) {
		header_length = 23;
		id_length = 2;
	} else if((version & 0xF) == 8) {
		header_length = 24;
		id_length = 2;
	} else {
		header_length = 28;
		id_length = 4;
	}
	media_type = ac_header[HEADER_FIELD_MEDIA_TYPE_BYTE_NO];
	trace_point = ac_header[HEADER_FIELD_TRACE_PT_BYTE_NO];
	extra_data = ac_header[HEADER_FIELD_DATA_BYTE_NO];
	if(id_length == 2) {
		source_id = ntohs(*(u_int16_t*)(ac_header + HEADER_FIELD_SRC_ID_BYTE_NO));
		dest_id = ntohs(*(u_int16_t*)(ac_header + HEADER_FIELD_DEST_ID_BYTE_NO));
	} else {
		source_id = ntohl(*(u_int32_t*)(ac_header + HEADER_FIELD_SRC_ID_BYTE_NO));
		dest_id = ntohl(*(u_int32_t*)(ac_header + HEADER_FIELD_DEST_ID_BYTE_NO));
	}
	if((version & 0xF) <= 3) {
		timestamp = (ntohl(*(u_int32_t*)(ac_header + HEADER_FIELD_TIME_BYTE_NO)) << 16) |
			    ntohs(*(u_int16_t*)(ac_header + HEADER_FIELD_TIME_BYTE_NO + 1));
        } else {
		timestamp = ntohl(*(u_int32_t*)(ac_header + HEADER_FIELD_TIME_BYTE_NO));
	}
	if((version & 0xF) >= 4) {
		sequence_number = ntohs(*(u_int16_t*)(ac_header + HEADER_FIELD_SEQ_NUM_BYTE_NO));
	}
	if((version & 0xF) < 5) {
		payload_offset = ac_header[HEADER_FIELD_PL_OFFSET_BYTE_NO];
        } else {
		header_length_extension = ac_header[HEADER_FIELD_HEADER_EXT_LEN_BYTE_NO];
        }
        if((version & 0xF) >= 5) {
		if((version & 0xF) < 7) {
			session_id_length = HEADER_FIELD_SESSION_ID_BYTE_COUNT;
		} else if((version & 0xF) == 7) {
			session_id_length = HEADER_FIELD_FULL_SESSION_ID_BYTE_COUNT;
		} else {
			session_id_length = HEADER_FIELD_LONG_FULL_SESSION_ID_BYTE_COUNT;
		}
		memcpy(session_id, ac_header + HEADER_FIELD_SESSION_ID_BYTE_NO, session_id_length);
        }
	if(((version & 0xF) >= 3) && ((MEDIUM_MASK & extra_data) == MEDIUM_MASK)) {
		medium_mii = true;
	}
	if(((HEADERADDED_MASK & extra_data) == HEADERADDED_MASK) && (extra_data != 0xAA)) {
		header_added = true;
	}
	header_length_total = header_length + header_length_extension;
	if(medium_mii) {
		header_length_total += MII_HEADER_BYTE_LENGTH;
	}
	if(header_length_extension > 0) {
		switch(media_type) {
		case ac_mt_T38:
			if(header_added) {
				int _udp_source_port_offset;
				if(header_length_extension == 12) {
					header_length_extension = 4;
					_udp_source_port_offset = header_length_total - 8;
				} else {
					_udp_source_port_offset = header_length_total;
				}
				t38_udp_port = ntohs(*(u_int16_t*)(ac_header + _udp_source_port_offset));
				t38_udp_dest_port = ntohs(*(u_int16_t*)(ac_header + _udp_source_port_offset + 2));
				if(t38_udp_dest_port < t38_udp_port) {
					t38_udp_port = t38_udp_dest_port;
				}
				break;
			}
		case ac_mt_RTP_AMR:
		case ac_mt_RTP_EVRC:
		case ac_mt_RTP_RFC2198:
		case ac_mt_RTP_RFC2833:
		case ac_mt_RTP_FEC:
			payload_type = ac_header[header_length_total + 1] & 0x7F;
			break;
		}
		bool _ipv6 = ((IPV6_MASK & extra_data) == IPV6_MASK);
		if((trace_point == ac_tp_DspIncoming) || (trace_point == ac_tp_DspOutgoing)) {
			/*
			//Gen5 only - special case of recorded packets from DSP
			proto_tree_add_item(extensionTree, hf_acdr_ext_dsp_core, tvb,
					    HEADER_BYTE_LENGTH,
					    1,
					    FALSE);
			proto_tree_add_item(extensionTree, hf_acdr_ext_dsp_channel, tvb,
					    HEADER_BYTE_LENGTH +1,
					    1,
					    FALSE);
			*/
			return(true);
		}
		switch(media_type) {
		case ac_mt_CAS:
		case ac_mt_NET_BRICKS:
			/*
			proto_tree_add_item(extensionTree, hf_acdr_ext_pstn_trace_seq_num, tvb,
					    HEADER_BYTE_LENGTH,
					    4,
					    FALSE);
			*/
			break;
		case ac_mt_Event:
			/*
			proto_tree_add_item(extensionTree, hf_acdr_ext_event_id, tvb,
					    HEADER_BYTE_LENGTH,
					    1,
					    FALSE);
			proto_tree_add_item(extensionTree, hf_acdr_ext_event_source, tvb,
					    HEADER_BYTE_LENGTH +1,
					    1,
					    FALSE);
			*/
			break;
		case ac_mt_DSP_AC49X:
		case ac_mt_DSP_AC48X:
		case ac_mt_DSP_AC45X:
		case ac_mt_DSP_AC5X:
		case ac_mt_DSP_AC5X_MII:
		case ac_mt_DSP_SNIFFER:
			/*
			proto_tree_add_item(extensionTree, hf_acdr_ext_dsp_core, tvb,
					    HEADER_BYTE_LENGTH,
					    1,
					    FALSE);
			proto_tree_add_item(extensionTree, hf_acdr_ext_dsp_channel, tvb,
					    HEADER_BYTE_LENGTH +1,
					    1,
					    FALSE);
			*/
			break;
		case ac_mt_RTP:
		case ac_mt_RTP_AMR:
		case ac_mt_RTP_EVRC:
		case ac_mt_RTP_RFC2198:
		case ac_mt_RTP_RFC2833:
		case ac_mt_T38_OVER_RTP:
		case ac_mt_RTP_FEC:
		case ac_mt_RTP_FAX_BYPASS:
		case ac_mt_RTP_MODEM_BYPASS:
		case ac_mt_RTP_NSE:
		case ac_mt_RTP_NO_OP:
		case ac_mt_T38:
		case ac_mt_RTCP:
		case ac_mt_VIDEORTP:
		case ac_mt_VIDEORTCP:
		case ac_mt_NATIVE:
		case ac_mt_DTLS:
			{
			u_int8_t _ext_ip_bytes = EXT_HEADER_IPV4_ADDRESS_BYTE_COUNT;
			if((version & 0xF) == 3) {
			    _ext_ip_bytes = EXT_HEADER_IPV6_ADDRESS_BYTE_COUNT;
			} else if((version & 0xF) >= 4) {
				_ext_ip_bytes = _ipv6 ? EXT_HEADER_IPV6_ADDRESS_BYTE_COUNT : EXT_HEADER_IPV4_ADDRESS_BYTE_COUNT;
			}
			if((trace_point == ac_tp_Net2Dsp) || (trace_point == ac_tp_Net2Host)  || (trace_point == ac_tp_DspDecoder)  || (trace_point == ac_tp_VoipDecoder) ||
			   (trace_point == ac_tp_Net2DspPing) || (trace_point == ac_tp_AfterSrtpDecoder)) {
				if(((version & 0xF) >= 3) && _ipv6) {
					set_ip(&packet_source_ip, ac_header + header_length, 6); 
				} else {
					set_ip(&packet_source_ip, ac_header + header_length); 
				}
				if((media_type == ac_mt_T38) && (trace_point == ac_tp_Net2Dsp) && (header_length_extension == 4)) {
					// Gen3 only: we put the UDP header in the last 8 bytes of the header extension.
					//           So, we have only IP address into the real header extension
					break;
				}
				set_port(&packet_source_port, ac_header + header_length + _ext_ip_bytes);
				set_port(&packet_dest_port, ac_header + header_length + _ext_ip_bytes + EXT_HEADER_UDP_PORT_BYTE_COUNT);
				ip_type_of_service = ac_header[header_length + _ext_ip_bytes + EXT_HEADER_UDP_PORT_BYTE_COUNT + EXT_HEADER_UDP_PORT_BYTE_COUNT];
				if((trace_point == ac_tp_Net2Dsp) && (header_length_extension == 10)) {
					/*
					// Gen3 only: we should add one byte of C5 Control Flags
					// C5 Control Flags
					guint32 C5CntrlFlagsBytes = HEADER_BYTE_LENGTH + _ext_ip_bytes + EXT_HEADER_UDP_PORT_BYTE_COUNT + EXT_HEADER_UDP_PORT_BYTE_COUNT + EXT_HEADER_IP_TOS_BYTE_COUNT;
					CreateC5CntrlFlagsSubtree(extensionTree, tvb, C5CntrlFlagsBytes);
					*/
				}
			}
			else if((trace_point == ac_tp_Dsp2Net) || (trace_point == ac_tp_Host2Net) || (trace_point == ac_tp_P2P) || (trace_point == ac_tp_P2PDecoder) ||
				(trace_point == ac_tp_P2PEncoder) || (trace_point == ac_tp_NetEncoder) || (trace_point == ac_tp_VoipEncoder)  || (trace_point == ac_tp_DspEncoder) ||
				(trace_point == ac_tp_Dsp2NetPing)) {
				if(((version & 0xF) >= 3) && _ipv6) {
					set_ip(&packet_dest_ip, ac_header + header_length, 6); 
				} else {
					set_ip(&packet_dest_ip, ac_header + header_length); 
				}
				if((media_type == ac_mt_T38) && (trace_point == ac_tp_Dsp2Net) && (header_length_extension == 4)){
					// Gen3 only: we put the UDP header in the last 8 bytes of the header extension.
					//           So, we have only IP address into the real header extension
					break;
				}
				set_port(&packet_dest_port, ac_header + header_length + _ext_ip_bytes);
				set_port(&packet_source_port, ac_header + header_length + _ext_ip_bytes + EXT_HEADER_UDP_PORT_BYTE_COUNT);
				ip_type_of_service = ac_header[header_length + _ext_ip_bytes + EXT_HEADER_UDP_PORT_BYTE_COUNT + EXT_HEADER_UDP_PORT_BYTE_COUNT];
			} else {
				/*
				proto_tree_add_item(extensionTree, hf_acdr_payload_header, tvb,
						    HEADER_BYTE_LENGTH,
						    extensionLength,
						    FALSE);
				*/
			}
			}
			break;
		case ac_mt_SIP:
		case ac_mt_MEGACO:
		case ac_mt_MGCP:
		case ac_mt_TPNCP:
		case ac_mt_Control:
			if(trace_point == ac_tp_System) {
				set_ip(&packet_source_ip, ac_header + header_length);
				set_ip(&packet_dest_ip, ac_header + header_length + 4);
				set_port(&packet_source_port, ac_header + header_length + 8);
				set_port(&packet_source_port, ac_header + header_length + 10);
				ip_protocol_type = ac_header[header_length + 12];
				packet_direction = ac_header[header_length + 13];
			} else {
				/*
				proto_tree_add_item(extensionTree, hf_acdr_payload_header, tvb,
						    HEADER_BYTE_LENGTH,
						    extensionLength,
						    FALSE);
				*/
			}
			break;
		case ac_mt_TLS:
		case ac_mt_TLSPeek:
			/*
			TlsPacketInfo->SourcePort = tvb_get_ntohs(tvb, HEADER_BYTE_LENGTH);
			TlsPacketInfo->DestPort = tvb_get_ntohs(tvb, HEADER_BYTE_LENGTH+2);
			TlsPacketInfo->Application = tvb_get_guint8(tvb, HEADER_BYTE_LENGTH+12);

			proto_tree_add_item(extensionTree, hf_acdr_ext_srcudp, tvb,
					    HEADER_BYTE_LENGTH,
					    2,
					    FALSE);

			proto_tree_add_item(extensionTree, hf_acdr_ext_dstudp, tvb,
					    HEADER_BYTE_LENGTH+2,
					    2,
					    FALSE);

			proto_tree_add_item(extensionTree, hf_acdr_ext_srcip, tvb,
					    HEADER_BYTE_LENGTH +4,
					    4,
					    FALSE);

			proto_tree_add_item(extensionTree, hf_acdr_ext_dstip, tvb,
					    HEADER_BYTE_LENGTH +8,
					    4,
					    FALSE);


			proto_tree_add_item(extensionTree, hf_acdr_ext_tls_application, tvb,
					    HEADER_BYTE_LENGTH +12,
					    1,
					    FALSE);
			*/
			break;
		case ac_mt_ATMAAL1:
		case ac_mt_ATMAAL2:
		case ac_mt_ATMAAL5:
			/*
			proto_tree_add_item(extensionTree, hf_acdr_ext_atm_port, tvb,
					    HEADER_BYTE_LENGTH,
					    1,
					    FALSE);
			*/
			break;
		case ac_mt_AAL2:
			/*
			if (tracePoint == Net2Dsp)
			{
			    proto_tree_add_item(extensionTree, hf_acdr_ext_src_vpi, tvb,
						HEADER_BYTE_LENGTH,
						4,
						FALSE);

			    proto_tree_add_item(extensionTree, hf_acdr_ext_src_vci, tvb,
						HEADER_BYTE_LENGTH,
						4,
						FALSE);

			    proto_tree_add_item(extensionTree, hf_acdr_ext_atm_port, tvb,
						HEADER_BYTE_LENGTH+4,
						1,
						FALSE);
			}
			else if (tracePoint == Dsp2Net)
			{
			    proto_tree_add_item(extensionTree, hf_acdr_ext_dst_vpi, tvb,
						HEADER_BYTE_LENGTH,
						4,
						FALSE);

			    proto_tree_add_item(extensionTree, hf_acdr_ext_dst_vci, tvb,
						HEADER_BYTE_LENGTH,
						4,
						FALSE);

			    proto_tree_add_item(extensionTree, hf_acdr_ext_atm_port, tvb,
						HEADER_BYTE_LENGTH+4,
						1,
						FALSE);
			}
			else
			{
			    proto_tree_add_item(extensionTree, hf_acdr_payload_header, tvb,
						HEADER_BYTE_LENGTH,
						extensionLength,
						FALSE);
			}
			break;
			*/
			break;
		default:
			/*
			//Payload Header - only show it if exists
			proto_tree_add_item(extensionTree, hf_acdr_payload_header, tvb,
					    HEADER_BYTE_LENGTH,
					    extensionLength,
					    FALSE);
			*/
			{}
		}
	}
	return(true);
}

void sAudiocodes::set_ip(vmIP *ip, u_char *data, bool ipv6) {
	#if VM_IPV6
	if(ipv6) {
		ip->setIPv6(*(in6_addr*)data, true);
	} else {
	#endif
		ip->setIPv4(*(u_int32_t*)data, true);
	#if VM_IPV6
	}
	#endif
}

void sAudiocodes::set_port(vmPort *port, u_char *data) {
	port->setPort(*(u_int16_t*)data, true);
}

iphdr2* sAudiocodes::get_iphdr(u_char *ac_header) {
	switch(ip_protocol_type) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
		return((iphdr2*)(ac_header + header_length_total));
		break;
	}
	return(NULL);
}

udphdr2* sAudiocodes::get_udphdr(u_char *ac_header) {
	switch(ip_protocol_type) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
		iphdr2 *iphdr = get_iphdr(ac_header);
		if(iphdr && iphdr->get_protocol() == IPPROTO_UDP) {
			return((udphdr2*)(ac_header + header_length_total + iphdr->get_hdr_size()));
		}
		break;
	}
	return(NULL);
}

tcphdr2* sAudiocodes::get_tcphdr(u_char *ac_header) {
	switch(ip_protocol_type) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
		iphdr2 *iphdr = get_iphdr(ac_header);
		if(iphdr && iphdr->get_protocol() == IPPROTO_TCP) {
			return((tcphdr2*)(ac_header + header_length_total + iphdr->get_hdr_size()));
		}
		break;
	}
	return(NULL);
}

u_char* sAudiocodes::get_data(u_char *ac_header) {
	switch(ip_protocol_type) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
		iphdr2 *iphdr = get_iphdr(ac_header);
		if(iphdr) {
			switch(iphdr->get_protocol()) {
			case IPPROTO_UDP:
				return(ac_header + header_length_total + iphdr->get_hdr_size() + sizeof(udphdr2));
			case IPPROTO_TCP:
				tcphdr2 *tcphdr = (tcphdr2*)(ac_header + header_length_total + iphdr->get_hdr_size());
				return(ac_header + header_length_total + iphdr->get_hdr_size() + tcphdr->doff * 4);
			}
		}
		break;
	}
	return(ac_header + header_length_total);
}

unsigned sAudiocodes::get_data_offset(u_char *ac_header) {
	switch(ip_protocol_type) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
		iphdr2 *iphdr = get_iphdr(ac_header);
		if(iphdr) {
			switch(iphdr->get_protocol()) {
			case IPPROTO_UDP:
				return(header_length_total + iphdr->get_hdr_size() + sizeof(udphdr2));
			case IPPROTO_TCP:
				tcphdr2 *tcphdr = (tcphdr2*)(ac_header + header_length_total + iphdr->get_hdr_size());
				return(header_length_total + iphdr->get_hdr_size() + tcphdr->doff * 4);
			}
		}
		break;
	}
	return(header_length_total);
}
