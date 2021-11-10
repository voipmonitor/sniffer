#ifndef IP_H
#define IP_H

#if defined(CLOUD_ROUTER_SERVER) or defined(CLOUD_ROUTER_CLIENT)
#include "config.h"
#endif

#ifndef VM_IPV6
#define VM_IPV6 true
#endif

#if VM_IPV6
    extern bool useIPv6;
    #define VM_IPV6_B useIPv6
#else
    #define VM_IPV6_B false
#endif
#define VM_IPV6_TYPE_MYSQL_COLUMN (VM_IPV6_B ? "varbinary(16)" : "int unsigned")


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <string>
#include <math.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <string.h>
#include <stdlib.h>

#include "endian.h"


#ifdef FREEBSD
#define	__in6_u	__u6_addr
#endif
#define IP_STR_MAX_LENGTH 50
    
#define IPPROTO_ESP_HEADER_SIZE 8
#define IPPROTO_ESP_FOOTER_SIZE 14


struct vmIP {
	inline vmIP(u_int32_t ip = 0) {
		this->ip.v4.n = ip;
		#if VM_IPV6
			v6 = false;
		#endif
	}
	#if VM_IPV6
	inline vmIP(in6_addr ip) {
		this->ip.v6 = ip;
		v6 = true;
	}
	#endif
	void setIP(u_char *data_ip, unsigned data_ip_length, bool varbinary) {
		clear();
		#if VM_IPV6
		if(varbinary) {
			switch(data_ip_length) {
			case 4:
				ip.v4.n = ntohl(*(u_int32_t*)data_ip);
				v6 = false;
				break;
			case 8:
			case 9:
			case 10:
				{
				unsigned int ipl = 0;
				for(unsigned i = 0; i < data_ip_length; i++) {
					ipl = ipl * 10 + (data_ip[i] - 0x30);
				}
				ip.v4.n = ipl;
				v6 = false;
				}
				break;
			case 16:
				memcpy((u_char*)&ip.v6 + (sizeof(ip.v6) - data_ip_length), data_ip, data_ip_length);
				for(unsigned i = 0; i < 4; i++) {
					 ip.v6.__in6_u.__u6_addr32[i] = ntohl(ip.v6.__in6_u.__u6_addr32[i]);
				}
				v6 = true;
				break;
			}
		} else {
		#endif
			ip.v4.n = atol((char*)data_ip);
		#if VM_IPV6
		}
		#endif
	}
	void setIP(void *db_row, const char *field);
	inline void setIPv4(u_int32_t ip, bool ntoh = false) {
		this->ip.v4.n = ip;
		if(ntoh) {
			this->ip.v4.n = ntohl(this->ip.v4.n);
		}
		#if VM_IPV6
			v6 = false;
		#endif
	}
	#if VM_IPV6
	inline void setIPv6(in6_addr ip, bool ntoh = false) {
		this->ip.v6 = ip;
		if(ntoh) {
			for(unsigned i = 0; i < 4; i++) {
				this->ip.v6.__in6_u.__u6_addr32[i] = ntohl(this->ip.v6.__in6_u.__u6_addr32[i]);
			}
		}
		v6 = true;
	}
	#endif
	inline u_int32_t getIPv4(bool hton = false) const {
		return(hton ?
			htonl(this->ip.v4.n) :
			this->ip.v4.n);
	}
	#if VM_IPV6
	inline in6_addr getIPv6(bool hton = false) const {
		if(hton) {
			in6_addr _ip = this->ip.v6;
			for(unsigned i = 0; i < 4; i++) {
				_ip.__in6_u.__u6_addr32[i] = htonl(_ip.__in6_u.__u6_addr32[i]);
			}
			return(_ip);
		} else {
			return(this->ip.v6);
		}
	}
	#endif
	bool setFromString(const char *ip);
	bool setFromString(const char *ip, const char **end_ptr);
	std::string getString(bool ipv6_in_brackets = false) const;
	std::string getStringForMysqlIpColumn(const char *table, const char *column) const;
	std::string _getStringForMysqlIpColumn(int IPv) const;
	inline bool isLocalhost() {
		#if VM_IPV6
		if(!v6) {
		#endif
			return((ip.v4.n >> 8) == 0x7F0000);
		#if VM_IPV6
		} else {
			return((ip.v6.__in6_u.__u6_addr32[0] == 0 &&
				ip.v6.__in6_u.__u6_addr32[1] == 0 &&
				ip.v6.__in6_u.__u6_addr32[2] == 0 &&
				ip.v6.__in6_u.__u6_addr32[3] == 1) ||
			       (ip.v6.__in6_u.__u6_addr32[0] == 0 &&
				ip.v6.__in6_u.__u6_addr32[1] == 0 &&
				ip.v6.__in6_u.__u6_addr32[2] == 0xFFFF &&
				(ip.v6.__in6_u.__u6_addr32[3] >> 8) == 0x7F0000));
		}
		#endif
	}
	bool isLocalIP();
	inline bool operator == (const vmIP& other) const {
		#if VM_IPV6
		return(this->v6 == other.v6 &&
		       (this->v6 ?
			 !memcmp(&this->ip.v6, &other.ip.v6, sizeof(this->ip.v6)) :
			 this->ip.v4.n == other.ip.v4.n)); 
		#else
		return(this->ip.v4.n == other.ip.v4.n);
		#endif
	}
	inline bool operator != (const vmIP& other) const {
		return(!(*this == other));
	}
	inline bool operator < (const vmIP& other) const { 
		#if VM_IPV6
		return(this->v6 != other.v6 ?
			this->v6 < other.v6 :
			(this->v6 ?
			  memcmp(&this->ip.v6, &other.ip.v6, sizeof(this->ip.v6)) < 0 :
			  this->ip.v4.n < other.ip.v4.n)); 
		#else
		return(this->ip.v4.n < other.ip.v4.n);
		#endif
	}
	inline bool operator <= (const vmIP& other) const { 
		return(*this < other ||
		       *this == other); 
	}
	inline bool operator > (const vmIP& other) const { 
		return(!(*this <= other));
	}
	inline bool operator >= (const vmIP& other) const { 
		return(*this > other ||
		       *this == other); 
	}
	inline bool isSet() const {
		#if VM_IPV6
		if(!v6) {
		#endif
			return(ip.v4.n != 0);
		#if VM_IPV6
		} else {
			return(ip.v6.__in6_u.__u6_addr32[0] != 0 ||
			       ip.v6.__in6_u.__u6_addr32[1] != 0 ||
			       ip.v6.__in6_u.__u6_addr32[2] != 0 ||
			       ip.v6.__in6_u.__u6_addr32[3] != 0);
		}
		#endif
	}
	inline void clear(u_int32_t set = 0) {
		#if VM_IPV6
		v6 = false;
		ip.v6.__in6_u.__u6_addr32[0] = set;
		ip.v6.__in6_u.__u6_addr32[1] = set;
		ip.v6.__in6_u.__u6_addr32[2] = set;
		ip.v6.__in6_u.__u6_addr32[3] = set;
		#else
		ip.v4.n = set;
		#endif
	}
	inline vmIP _and(vmIP mask) {
		vmIP ip = *this;
		#if VM_IPV6
		if(!v6) {
		#endif
			ip.ip.v4.n &= mask.ip.v4.n;
		#if VM_IPV6
		} else {
			for(unsigned i = 0; i < 4; i++) {
				ip.ip.v6.__in6_u.__u6_addr32[i] &= mask.ip.v6.__in6_u.__u6_addr32[i];
			}
		}
		#endif
		return(ip);
	}
	inline vmIP _or(vmIP mask) {
		vmIP ip = *this;
		#if VM_IPV6
		if(!v6) {
		#endif
			ip.ip.v4.n |= mask.ip.v4.n;
		#if VM_IPV6
		} else {
			for(unsigned i = 0; i < 4; i++) {
				ip.ip.v6.__in6_u.__u6_addr32[i] |= mask.ip.v6.__in6_u.__u6_addr32[i];
			}
		}
		#endif
		return(ip);
	}
	inline vmIP mask(vmIP mask) {
		return(_and(mask));
	}
	inline vmIP network_mask(unsigned mask, bool enable_zero = false) {
		vmIP ip;
		#if VM_IPV6
		if(!v6) {
			ip.v6 = false;
		#endif
			if(!mask && !enable_zero) {
				mask = 32;
			}
			ip.ip.v4.n = mask == 0 ? 0 : ((u_int32_t)-1 << (32 - mask)) & (u_int32_t)-1;
		#if VM_IPV6
		} else {
			if(!mask) {
				mask = 128;
			}
			ip.v6 = true;
			for(unsigned i = 0; i < 4; i++) {
				int _mask = mask - i * 32;
				if(mask == 0 || _mask <= 0) {
					ip.ip.v6.__in6_u.__u6_addr32[i] = 0;
				} else if(_mask >= 32) {
					ip.ip.v6.__in6_u.__u6_addr32[i] = (u_int32_t)-1;
				} else {
					ip.ip.v6.__in6_u.__u6_addr32[i] = ((u_int32_t)-1 << (32 - _mask)) & (u_int32_t)-1;
				}
			}
		}
		#endif
		return(ip);
	}
	inline vmIP wildcard_mask(unsigned mask, bool enable_zero = false) {
		vmIP ip;
		#if VM_IPV6
		if(!v6) {
			ip.v6 = false;
		#endif
			if(!mask && !enable_zero) {
				mask = 32;
			}
			ip.ip.v4.n = mask == 0 ? (u_int32_t)-1 : (u_int32_t)(pow(2, 32 - mask) - 1);
		#if VM_IPV6
		} else {
			if(!mask) {
				mask = 128;
			}
			ip.v6 = true;
			for(unsigned i = 0; i < 4; i++) {
				int _mask = mask - i * 32;
				if(mask == 0 || _mask <= 0) {
					ip.ip.v6.__in6_u.__u6_addr32[i] = (u_int32_t)-1;
				} else if(_mask >= 32) {
					ip.ip.v6.__in6_u.__u6_addr32[i] = 0;
				} else {
					ip.ip.v6.__in6_u.__u6_addr32[i] = (u_int32_t)(pow(2, 32 -_mask) - 1);
				}
			}
		}
		#endif
		return(ip);
	}
	inline vmIP network(unsigned mask, bool enable_zero = false) {
		return(this->_and(this->network_mask(mask, enable_zero)));
	}
	inline vmIP broadcast(unsigned mask, bool enable_zero = false) {
		return(this->_or(this->wildcard_mask(mask, enable_zero)));
	}
	inline u_int32_t getHashNumber() {
		#if VM_IPV6
		if(!v6) {
		#endif
			return(ip.v4.n);
		#if VM_IPV6
		} else {
			return(ip.v6.__in6_u.__u6_addr32[3]);
		}
		#endif
	}
	inline void *getPointerToIP() {
		#if VM_IPV6
		if(!v6) {
		#endif
			return(&ip.v4.n);
		#if VM_IPV6
		} else {
			return(&ip.v6);
		}
		#endif
	}
	inline bool is_v6() {
		#if VM_IPV6
			return(v6);
		#else
			return(false);
		#endif
	}
	inline u_int8_t bits() const {
		#if VM_IPV6
			return(v6 ? 128 : 32);
		#else
			return(32);
		#endif
	}
	inline bool is_net_mask(int bits) {
		return(bits > 0 && bits < this->bits());
	}
	inline void set_to_v6() {
		#if VM_IPV6
		v6 = true;
		for(unsigned i = 0; i < sizeof(ip.v4.filler) / sizeof(ip.v4.filler[0]); i++) {
			ip.v4.filler[i] = 0;
		}
		#endif
	}
	inline void set_to_v4() {
		#if VM_IPV6
		v6 = false;
		#endif
	}
	#if VM_IPV6
		u_int8_t v6;
	#endif
	union {
		struct {
			#if VM_IPV6
			u_int32_t filler[3];
			#endif
			u_int32_t n;
		} v4;
		#if VM_IPV6
		in6_addr v6;
		#endif
	} ip;
};


#define IP6_EXT_HEADERS_MAX 10


#if VM_IPV6
struct ip6hdr2 {
	inline vmIP get_saddr() {
		in6_addr __saddr = _saddr;
		for(unsigned i = 0; i < 4; i++) {
			__saddr.__in6_u.__u6_addr32[i] = ntohl(__saddr.__in6_u.__u6_addr32[i]);
		}
		return(__saddr);
	}
	inline vmIP get_daddr() {
		in6_addr __daddr = _daddr;
		for(unsigned i = 0; i < 4; i++) {
			__daddr.__in6_u.__u6_addr32[i] = ntohl(__daddr.__in6_u.__u6_addr32[i]);
		}
		return(__daddr);
	}
	inline void set_saddr(vmIP &ip) {
		_saddr = ip.getIPv6();
		for(unsigned i = 0; i < 4; i++) {
			_saddr.__in6_u.__u6_addr32[i] = htonl(_saddr.__in6_u.__u6_addr32[i]);
		}
	}
	inline void set_daddr(vmIP &ip) {
		_daddr = ip.getIPv6();
		for(unsigned i = 0; i < 4; i++) {
			_daddr.__in6_u.__u6_addr32[i] = htonl(_daddr.__in6_u.__u6_addr32[i]);
		}
	}
	static inline bool is_ext_header(u_int8_t header_id) {
		return(header_id == IPPROTO_HOPOPTS ||
		       header_id == IPPROTO_ROUTING ||
		       header_id == IPPROTO_FRAGMENT ||
		       header_id == IPPROTO_ICMPV6 ||
		       header_id == IPPROTO_NONE ||
		       header_id == IPPROTO_DSTOPTS
		       #ifdef IPPROTO_MH
		       || header_id == IPPROTO_MH
		       #endif
		       );
	}
	static inline u_int16_t get_ext_header_size(u_char *header, u_int8_t header_id) {
		return(header_id == IPPROTO_HOPOPTS ? ((ip6_hbh*)header)->ip6h_len :
		       header_id == IPPROTO_ROUTING ? ((ip6_rthdr*)header)->ip6r_len :
		       header_id == IPPROTO_FRAGMENT ? sizeof(ip6_frag) :
		       header_id == IPPROTO_ICMPV6 ? ((ip6_ext*)header)->ip6e_len :
		       header_id == IPPROTO_NONE ? ((ip6_ext*)header)->ip6e_len :
		       header_id == IPPROTO_DSTOPTS ? ((ip6_dest*)header)->ip6d_len :
		       #ifdef IPPROTO_MH
		       header_id == IPPROTO_MH ? ((ip6_ext*)header)->ip6e_len :
		       #endif
		       0);
	}
	static inline u_int16_t get_ext_header_nxt(u_char *header, u_int8_t header_id) {
		return(header_id == IPPROTO_HOPOPTS ? ((ip6_hbh*)header)->ip6h_nxt :
		       header_id == IPPROTO_ROUTING ? ((ip6_rthdr*)header)->ip6r_nxt :
		       header_id == IPPROTO_FRAGMENT ? ((ip6_frag*)header)->ip6f_nxt :
		       header_id == IPPROTO_ICMPV6 ? ((ip6_ext*)header)->ip6e_nxt :
		       header_id == IPPROTO_NONE ? ((ip6_ext*)header)->ip6e_nxt :
		       header_id == IPPROTO_DSTOPTS ? ((ip6_dest*)header)->ip6d_nxt :
		       #ifdef IPPROTO_MH
		       header_id == IPPROTO_MH ? ((ip6_ext*)header)->ip6e_nxt :
		       #endif
		       0);
	}
	inline u_int32_t get_tot_len() {
		return(sizeof(ip6hdr2) + ntohs(this->plen));
	}
	inline void set_tot_len(u_int32_t tot_len) {
		this->plen = htons(tot_len - sizeof(ip6hdr2));
	}
	inline u_int8_t get_tos() {
		return(0);
	}
	inline u_int32_t get_frag_id() {
		ip6_frag *frag = (ip6_frag*)get_ext_header(IPPROTO_FRAGMENT);
		return(frag ? ntohl(frag->ip6f_ident) : 0);
	}
	inline u_int16_t get_frag_data() {
		ip6_frag *frag = (ip6_frag*)get_ext_header(IPPROTO_FRAGMENT);
		return(frag ? ntohs(frag->ip6f_offlg) : 0);
	}
	inline bool is_more_frag(u_int16_t frag_data) {
		return(frag_data & 1);
	}
	inline u_int16_t get_frag_offset(u_int16_t frag_data) {
		return(frag_data >> 3 << 3);
	}
	inline void clear_frag_data() {
		ip6_frag *frag = (ip6_frag*)get_ext_header(IPPROTO_FRAGMENT);
		if(frag) {
			frag->ip6f_offlg = 0;
		}
	}
	inline u_int8_t _get_protocol() {
		return(get_ext_headers(NULL, 0, NULL));
	}
	inline u_int8_t get_protocol() {
		u_int8_t proto = _get_protocol();
		if(proto == IPPROTO_ESP) {
			proto = *(u_int8_t*)((u_char*)this + get_tot_len() - IPPROTO_ESP_FOOTER_SIZE + 1);
		}
		return(proto);
	}
	inline void set_protocol(u_int8_t protocol) {
		nxt = protocol;
	}
	inline u_int16_t _get_hdr_size() {
		return(get_total_headers_len());
	}
	inline u_int16_t get_hdr_size(u_int8_t *proto_rslt = NULL) {
		u_int8_t proto;
		u_int16_t hdr_size = get_total_headers_len(&proto);
		if(proto_rslt) {
			*proto_rslt = proto;
		}
		if(hdr_size == (u_int16_t)-1) {
			return(-1);
		}
		if(proto == IPPROTO_ESP) {
			hdr_size += IPPROTO_ESP_HEADER_SIZE;
		}
		return(hdr_size);
	}
	inline bool is_ext_headers() {
		return(is_ext_header(nxt));
	}
	u_int8_t get_ext_headers(u_int8_t *ext_headers_type, u_int8_t ext_headers_max, u_int8_t *ext_headers_count);
	u_int16_t get_ext_headers_len(u_int8_t *proto = NULL);
	inline u_int16_t get_total_headers_len(u_int8_t *proto = NULL) {
		u_int16_t ext_headers_len = get_ext_headers_len(proto);
		if(ext_headers_len == (u_int16_t)-1) {
			return(-1);
		}
		return(ext_headers_len + sizeof(ip6hdr2));
	}
	u_int16_t get_ext_header_offset(u_int8_t header_id);
	inline u_char *get_ext_header(u_int8_t header_id) {
		u_int16_t offset = get_ext_header_offset(header_id);
		return(offset == (u_int16_t)-1 ? NULL : (u_char*)this + offset);
	}
	#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned tc1:4;
	unsigned version:4;
	unsigned flow_id_1:4;
	unsigned tc2:4;
	unsigned flow_id_2:16;
	#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned version:4;
	unsigned tc1:4;
	unsigned tc2:4;
	unsigned flow_id_1:4;
	unsigned flow_id_2:16;
	#endif
	u_int16_t plen;
	u_int8_t  nxt;
	u_int8_t  hlim;
	in6_addr _saddr;
	in6_addr _daddr; 
};
#endif


struct iphdr2 {
	inline vmIP get_saddr() {
		#if VM_IPV6
		if(version == 4) {
		#endif
			return(ntohl(_saddr));
		#if VM_IPV6
		} else {
			return(((ip6hdr2*)this)->get_saddr());
		}
		#endif
	}
	inline vmIP get_daddr() {
		#if VM_IPV6
		if(version == 4) {
		#endif
			return(ntohl(_daddr));
		#if VM_IPV6
		} else {
			return(((ip6hdr2*)this)->get_daddr());
		}
		#endif
	}
	inline void set_saddr(vmIP &ip) {
		#if VM_IPV6
		if(version == 4) {
		#endif
			_saddr = htonl(ip.getIPv4());
		#if VM_IPV6
		} else {
			((ip6hdr2*)this)->set_saddr(ip);
		}
		#endif
	}
	inline void set_daddr(vmIP &ip) {
		#if VM_IPV6
		if(version == 4) {
		#endif
			_daddr = htonl(ip.getIPv4());
		#if VM_IPV6
		} else {
			((ip6hdr2*)this)->set_daddr(ip);
		}
		#endif
	}
	inline void _set_saddr(u_int32_t ip) {
		#if VM_IPV6
		if(version == 4) {
		#endif
			_saddr = ip;
		#if VM_IPV6
		} else {
		}
		#endif
	}
	inline void _set_daddr(u_int32_t ip) {
		#if VM_IPV6
		if(version == 4) {
		#endif
			_daddr = ip;
		#if VM_IPV6
		} else {
		}
		#endif
	}
	inline u_int32_t get_tot_len() {
		#if VM_IPV6
		if(version == 4) {
		#endif
			return(ntohs(_tot_len));
		#if VM_IPV6
		} else {
			return(((ip6hdr2*)this)->get_tot_len());
		}
		#endif
	}
	inline void set_tot_len(u_int32_t tot_len) {
		#if VM_IPV6
		if(version == 4) {
		#endif
			_tot_len = htons(tot_len);
		#if VM_IPV6
		} else {
			((ip6hdr2*)this)->set_tot_len(tot_len);
		}
		#endif
	}
	inline u_int8_t get_tos() {
		#if VM_IPV6
		if(version == 4) {
		#endif
			return(_tos);
		#if VM_IPV6
		} else {
			return(((ip6hdr2*)this)->get_tos());
		}
		#endif
	}
	inline u_int32_t get_frag_id() {
		#if VM_IPV6
		if(version == 4) {
		#endif
			return(ntohs(_id));
		#if VM_IPV6
		} else {
			return(((ip6hdr2*)this)->get_frag_id());
		}
		#endif
	}
	inline u_int16_t get_frag_data() {
		#if VM_IPV6
		if(version == 4) {
		#endif
			return(ntohs(_frag_off));
		#if VM_IPV6
		} else {
			return(((ip6hdr2*)this)->get_frag_data());
		}
		#endif
	}
	inline bool is_more_frag(u_int16_t frag_data) {
		#if VM_IPV6
		if(version == 4) {
		#endif
			return(frag_data & IP_MF);
		#if VM_IPV6
		} else {
			return(((ip6hdr2*)this)->is_more_frag(frag_data));
		}
		#endif
	}
	inline u_int16_t get_frag_offset(u_int16_t frag_data) {
		#if VM_IPV6
		if(version == 4) {
		#endif
			return((frag_data & IP_OFFMASK) << 3);
		#if VM_IPV6
		} else {
			return(((ip6hdr2*)this)->get_frag_offset(frag_data));
		}
		#endif
	}
	inline void clear_frag_data() {
		#if VM_IPV6
		if(version == 4) {
		#endif
			_frag_off = 0;
		#if VM_IPV6
		} else {
			((ip6hdr2*)this)->clear_frag_data();
		}
		#endif
	}
	inline u_int8_t get_ttl() {
		#if VM_IPV6
		if(version == 4) {
		#endif
			return(_ttl);
		#if VM_IPV6
		} else {
			return(0);
		}
		#endif
	}
	inline void set_ttl(u_int8_t ttl) {
		#if VM_IPV6
		if(version == 4) {
		#endif
			_ttl = ttl;
		#if VM_IPV6
		} else {
		}
		#endif
	}
	inline u_int8_t _get_protocol() {
		#if VM_IPV6
		if(version == 4) {
		#endif
			return(_protocol);
		#if VM_IPV6
		} else {
			return(((ip6hdr2*)this)->_get_protocol());
		}
		#endif
	}
	inline u_int8_t get_protocol() {
		#if VM_IPV6
		if(version == 4) {
		#endif
			if(_protocol == IPPROTO_ESP) {
				return(*(u_int8_t*)((u_char*)this + get_tot_len() - IPPROTO_ESP_FOOTER_SIZE + 1));
			} else {
				return(_protocol);
			}
		#if VM_IPV6
		} else {
			return(((ip6hdr2*)this)->get_protocol());
		}
		#endif
	}
	inline void set_protocol(u_int8_t protocol) {
		#if VM_IPV6
		if(version == 4) {
		#endif
			_protocol = protocol;
		#if VM_IPV6
		} else {
			((ip6hdr2*)this)->set_protocol(protocol);
		}
		#endif
	}
	inline u_int16_t get_hdr_size(u_int8_t *proto_rslt = NULL) {
		#if VM_IPV6
		if(version == 4) {
		#endif
			u_int16_t hdr_size = sizeof(iphdr2);
			if(_protocol == IPPROTO_ESP) {
				hdr_size += IPPROTO_ESP_HEADER_SIZE;
			}
			if(proto_rslt) {
				*proto_rslt = _protocol;
			}
			return(hdr_size);
		#if VM_IPV6
		} else {
			return(((ip6hdr2*)this)->get_hdr_size(proto_rslt));
		}
		#endif
	}
	inline u_int16_t get_footer_size(u_int8_t proto = (u_int8_t)-1) {
		if(proto == (u_int8_t)-1) {
			proto = _get_protocol();
		}
		if(proto == IPPROTO_ESP) {
			u_int8_t padding = *(u_int8_t*)((u_char*)this + get_tot_len() - IPPROTO_ESP_FOOTER_SIZE);
			return(IPPROTO_ESP_FOOTER_SIZE + padding);
		}
		return(0);
	}
	inline u_int16_t get_check() {
		#if VM_IPV6
		if(version == 4) {
		#endif
			return(ntohs(_check));
		#if VM_IPV6
		} else {
			return(0);
		}
		#endif
	}
	inline void set_check(u_int16_t check) {
		#if VM_IPV6
		if(version == 4) {
		#endif
			_check = htons(check);
		#if VM_IPV6
		} else {
		}
		#endif
	}
	inline u_int8_t get_ihl() {
		#if VM_IPV6
		if(version == 4) {
		#endif
			return(_ihl);
		#if VM_IPV6
		} else {
			return(0);
		}
		#endif
	}
	inline bool version_is_ok() {
		return(version == 4
		#if VM_IPV6
		|| version == 6
		#endif
		);
	}
	static inline iphdr2* create(unsigned version) {
		#if VM_IPV6
		if(version == 4) {
		#endif
			iphdr2 *iphdr = new iphdr2;
			memset(iphdr, 0, sizeof(*iphdr));
			iphdr->version = 4;
			iphdr->_ihl = 5;
			iphdr->_ttl = 50;
			return(iphdr);
		#if VM_IPV6
		} else {
			ip6hdr2 *iphdr = new ip6hdr2;
			memset(iphdr, 0, sizeof(*iphdr));
			iphdr->version = 6;
			return((iphdr2*)iphdr);
		}
		#endif
	}
#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned int _ihl:4;
	unsigned int version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned int version:4;
	unsigned int _ihl:4;
#else
# error "Please fix <bits/endian.h>"
#endif 
	u_int8_t _tos;
	u_int16_t _tot_len;
	u_int16_t _id;
	u_int16_t _frag_off;
	u_int8_t _ttl;
	u_int8_t _protocol;
	u_int16_t _check;
	u_int32_t _saddr;
	u_int32_t _daddr;
	/*The options start here. */
#ifdef PACKED
} __attribute__((packed));
#else
};
#endif


struct vmPort {
	inline vmPort(u_int16_t port = 0) {
		this->port = port;
	}
	inline void setPort(u_int16_t port, bool ntoh = false) {
		this->port = port;
		if(ntoh) {
			this->port = ntohs(this->port);
		}
	}
	inline u_int16_t getPort(bool hton = false) const {
		return(hton ?
			htons(this->port) :
			this->port);
	}
	inline operator int() const {
		return(port);
	}
	vmPort &setFromString(const char *port, bool inv = false) {
		this->port = atoi(port);
		if(inv) {
			this->port = htons(this->port);
		}
		return(*this);
	}
	std::string getString();
	inline bool operator == (const vmPort& other) const {
		return(this->port == other.port);
	}
	inline bool operator != (const vmPort& other) const {
		return(this->port != other.port);
	}
	inline bool operator < (const vmPort& other) const { 
		return(this->port < other.port);
	}
	inline bool operator > (const vmPort& other) const { 
		return(this->port > other.port);
	}
	inline bool isSet() const {
		return(port != 0);
	}
	inline void clear() {
		port = 0;
	}
	inline vmPort inc(int inc = 1) {
		vmPort port = *this;
		port.port += inc;
		return(port);
	}
	inline vmPort dec(int dec = 1) {
		vmPort port = *this;
		port.port -= dec;
		return(port);
	}
	u_int16_t port;
};

inline std::ostream& operator << (std::ostream& os, const vmPort &port) {
	os << port.getPort();
	return(os);
}

struct tcphdr2{ 
	inline vmPort get_source() {
		return(ntohs(_source));
	}
	inline vmPort get_dest() {
		return(ntohs(_dest));
	}
	inline void set_source(vmPort port) {
		_source = htons(port.port);
	}
	inline void set_dest(vmPort port) {
		_dest = htons(port.port);
	}
	u_int16_t _source;
	u_int16_t _dest;
	u_int32_t seq;
	u_int32_t ack_seq;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int16_t res1:4;
	u_int16_t doff:4;
	u_int16_t fin:1;
	u_int16_t syn:1;
	u_int16_t rst:1;
	u_int16_t psh:1;
	u_int16_t ack:1;
	u_int16_t urg:1;
	u_int16_t res2:2;
#  elif __BYTE_ORDER == __BIG_ENDIAN
	u_int16_t doff:4;
	u_int16_t res1:4;
	u_int16_t res2:2;
	u_int16_t urg:1;
	u_int16_t ack:1;
	u_int16_t psh:1;
	u_int16_t rst:1;
	u_int16_t syn:1;
	u_int16_t fin:1;
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
	u_int16_t window;
	u_int16_t check;
	u_int16_t urg_ptr;
};

struct udphdr2 {
	inline vmPort get_source() {
		return(ntohs(_source));
	}
	inline vmPort get_dest() {
		return(ntohs(_dest));
	}
	inline void set_source(vmPort port) {
		_source = htons(port.port);
	}
	inline void set_dest(vmPort port) {
		_dest = htons(port.port);
	}
        uint16_t        _source;
        uint16_t        _dest;
        uint16_t        len;
        uint16_t        check;
};


struct vmIPport {
	inline vmIPport() {
	}
	inline vmIPport(vmIP ip, vmPort port) {
		this->ip = ip;
		this->port = port;
	}
	inline bool operator == (const vmIPport& other) const {
		return(this->ip == other.ip &&
		       this->port == other.port);
	}
	inline bool operator < (const vmIPport& other) const { 
		return(this->ip < other.ip ||
		       (this->ip == other.ip && this->port < other.port));
	}
	inline bool operator > (const vmIPport& other) const { 
		return(this->ip > other.ip ||
		       (this->ip == other.ip && this->port > other.port));
	}
	std::string getString(bool ipv6_in_brackets = false) {
		return(ip.getString(ipv6_in_brackets) + ":" + port.getString());
	}
	vmIP ip;
	vmPort port;
};


struct vmIPmask_ {
	vmIPmask_() {
		ip.clear();
		mask = 0;
	}
	std::string getString(bool ipv6_in_brackets =  false) const {
		std::ostringstream outStr;
		outStr << ip.getString(ipv6_in_brackets);
		if(mask > 0 && mask < ip.bits()) {
			outStr << "/" << mask;
		}
		return(outStr.str());
	}
	bool setFromString(const char *ip_mask, const char **end_ptr = NULL) {
		clear();
		if(ip.setFromString(ip_mask, end_ptr)) {
			const char *mask_separator = strchr(end_ptr ? *end_ptr : ip_mask, '/');
			if(mask_separator) {
				++mask_separator;
				while(*mask_separator == ' ') {
					++mask_separator;
				}
				int _mask = atoi(mask_separator);
				if(_mask >= 0 && _mask <= ip.bits()) {
					mask = _mask;
				} else {
					mask = ip.bits();
				}
				if(end_ptr) {
					*end_ptr = mask_separator;
					while(isdigit(**end_ptr)) {
						++*end_ptr;
					}
				}
			} else {
				mask = ip.bits();
			}
			return(true);
		}
		return(false);
	}
	void clear() {
		ip.clear();
		mask = 0;
	}
	vmIP ip;
	u_int16_t mask;
};

struct vmIPmask : vmIPmask_ {
	vmIPmask() {
		ip.clear();
		mask = 0;
	}
	vmIPmask(vmIP ip, u_int16_t mask) {
		this->ip = ip;
		this->mask = mask;
	}
	inline bool operator < (const vmIPmask& other) const { 
		return(this->ip != other.ip ? this->ip < other.ip : this->mask < other.mask); 
	}
};

struct vmIPmask_order2 : vmIPmask_ {
	vmIPmask_order2() {
		ip.clear();
		mask = 0;
	}
	vmIPmask_order2(vmIP ip, u_int16_t mask) {
		this->ip = ip;
		this->mask = mask;
	}
	inline bool operator < (const vmIPmask_order2& other) const { 
		return(this->mask != other.mask ? this->mask < other.mask : this->ip < other.ip); 
	}
};


inline vmIP str_2_vmIP(const char *str) {
	vmIP vm_ip;
	vm_ip.setFromString(str);
	return(vm_ip);
}


inline vmIP ipv4_2_vmIP(u_int32_t ip, bool ntoh = false) {
	vmIP vm_ip;
	vm_ip.setIPv4(ip, ntoh);
	return(vm_ip);
}

inline bool ip_is_v4(const char *ips) {
	sockaddr_in sa;
	return(inet_pton(AF_INET, ips, &sa.sin_addr) != 0);
}

inline bool ip_is_v6(const char *ips) {
	struct sockaddr_in6 sa;
	return(inet_pton(AF_INET6, ips, &sa.sin6_addr) != 0);
}

inline int ip_is_valid(const char *ips) {
	return(ip_is_v4(ips) ? 4 :
	       ip_is_v6(ips) ? 6 : 0);
}

inline bool string_is_look_like_ipv4(const char *str) {
	return(isdigit(str[0]) && (str[1] == '.' ||
	       (isdigit(str[1]) && (str[2] == '.' ||
	       (isdigit(str[2]) && str[3] == '.')))));
}

inline bool string_is_look_like_ipv6(const char *str) {
	if(str[0] == '[') {
		return(string_is_look_like_ipv6(str + 1));
	}
	return((isxdigit(str[0]) && (str[1] == ':' ||
	       (isxdigit(str[1]) && (str[2] == ':' ||
	       (isxdigit(str[2]) && (str[3] == ':' ||
	       (isxdigit(str[3]) && str[4] == ':'))))))) ||
	       (str[0] == ':' && (isxdigit(str[1]) ||
	       (str[1] == ':' && isxdigit(str[2])))));
}

inline int string_is_look_like_ip(const char *str) {
	return(string_is_look_like_ipv4(str) ? 4 :
	       string_is_look_like_ipv6(str) ? 6 : 0);
}

vmIP mysql_ip_2_vmIP(void *row, const char *column);

void socket_set_saddr(sockaddr_in *addr, vmIP ip, vmPort port);
#if VM_IPV6
void socket_set_saddr(sockaddr_in6 *addr, vmIP ip, vmPort port);
#endif
int socket_create(vmIP ip, int type, int protocol);
int socket_connect(int socket, vmIP ip, vmPort port);
int socket_bind(int socket, vmIP ip, vmPort port);
int socket_accept(int socket, vmIP *ip, vmPort *port);


#endif //IP_H
