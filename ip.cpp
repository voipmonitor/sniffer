#include <arpa/inet.h>
#include <sys/socket.h>

#include "tools_global.h"

#include "ip.h"

#if defined(CLOUD_ROUTER_CLIENT) or defined(CLOUD_ROUTER_SERVER)
#include "sql_db.h"
#endif


#ifdef CLOUD_ROUTER_CLIENT
void vmIP::setIP(void *db_row, const char *field) {
	SqlDb_row *_db_row = (SqlDb_row*)db_row;
	setIP((u_char*)((*_db_row)[field].c_str()), _db_row->getLengthField(field), _db_row->getTypeField(field) == (int)MYSQL_TYPE_VAR_STRING);
}
#endif

bool vmIP::setFromString(const char *ip_str) {
	#if VM_IPV6
		if(strchr(ip_str, ':')) {
			v6 = true;
			if(ip_str[0] == '[') {
				unsigned ip_str_length = strlen(ip_str);
				if(ip_str[ip_str_length - 1] == ']') {
					char ip_str_tmp[100];
					strncpy(ip_str_tmp, ip_str + 1, min(ip_str_length - 2, (unsigned)sizeof(ip_str_tmp)));
					ip_str_tmp[min(ip_str_length - 2, (unsigned)sizeof(ip_str_tmp))] = 0;
					if(inet_pton(AF_INET6, ip_str_tmp, &ip.v6)) {
						for(unsigned i = 0; i < 4; i++) {
							ip.v6.__in6_u.__u6_addr32[i] = ntohl(ip.v6.__in6_u.__u6_addr32[i]);
						}
						return(true);
					}
				}
			} else {
				if(inet_pton(AF_INET6, ip_str, &ip.v6)) {
					for(unsigned i = 0; i < 4; i++) {
						ip.v6.__in6_u.__u6_addr32[i] = ntohl(ip.v6.__in6_u.__u6_addr32[i]);
					}
					return(true);
				}
			}
			clear();
			return(false);
		}
		v6 = false;
	#endif
	if(inet_pton(AF_INET, ip_str, &ip.v4.n)) {
		ip.v4.n = ntohl(ip.v4.n);
		return(true);
	} else {
		clear();
		return(false);
	}
}

bool vmIP::setFromString(const char *ip_str, const char **end_ptr) {
	if(end_ptr) {
		*end_ptr = NULL;
	}
	unsigned ip_str_offset = 0;
	while(ip_str[0] == ' ' || ip_str[0] == '\t') {
		++ip_str;
		++ip_str_offset;
	}
	#if VM_IPV6
		const char* ipv6_sep_pos = strchr(ip_str, ':');
		if(ipv6_sep_pos && (ipv6_sep_pos - ip_str) <= (ip_str[0] == '[' ? 5 : 4)) {
			v6 = true;
			if(ip_str[0] == '[') {
				++ip_str;
				++ip_str_offset;
			}
			unsigned ip_str_length = 0;
			while(ip_str[ip_str_length] && strchr("0123456789abcdefABCDEF:", ip_str[ip_str_length])) {
				++ip_str_length;
			}
			if(ip_str_length > 0) {
				char ip_str_tmp[100];
				strncpy(ip_str_tmp, ip_str, min(ip_str_length, (unsigned)sizeof(ip_str_tmp)));
				ip_str_tmp[min(ip_str_length, (unsigned)sizeof(ip_str_tmp))] = 0;
				if(inet_pton(AF_INET6, ip_str_tmp, &ip.v6)) {
					for(unsigned i = 0; i < 4; i++) {
						ip.v6.__in6_u.__u6_addr32[i] = ntohl(ip.v6.__in6_u.__u6_addr32[i]);
					}
					if(end_ptr) {
						*end_ptr = ip_str + ip_str_length + (ip_str[ip_str_length] == ']' ? 1 : 0);
					}
					return(true);
				}
			}
			clear();
			return(false);
		}
		v6 = false;
	#endif
	unsigned ip_str_length = 0;
	while(ip_str[ip_str_length] && strchr("0123456789.", ip_str[ip_str_length])) {
		++ip_str_length;
	}
	if(ip_str_length > 0) {
		char ip_str_tmp[100];
		strncpy(ip_str_tmp, ip_str, min(ip_str_length, (unsigned)sizeof(ip_str_tmp)));
		ip_str_tmp[min(ip_str_length, (unsigned)sizeof(ip_str_tmp))] = 0;
		if(inet_pton(AF_INET, ip_str_tmp, &ip.v4.n)) {
			ip.v4.n = ntohl(ip.v4.n);
			if(end_ptr) {
				*end_ptr = ip_str + ip_str_length;
			}
			return(true);
		}
	}
	clear();
	return(false);
}

std::string vmIP::getString(bool ipv6_in_brackets) const {
	#if VM_IPV6
		if(v6) {
			char ip_str[IP_STR_MAX_LENGTH];
			in6_addr ip_v6;
			for(unsigned i = 0; i < 4; i++) {
				ip_v6.__in6_u.__u6_addr32[i] = htonl(ip.v6.__in6_u.__u6_addr32[i]);
			}
			inet_ntop(AF_INET6, &ip_v6, ip_str, IP_STR_MAX_LENGTH);
			return(ipv6_in_brackets ? 
				string("[") + ip_str + "]" :
				ip_str);
		}
	#endif
	char ip_str[IP_STR_MAX_LENGTH];
	u_int32_t ip_v4 = htonl(ip.v4.n);
	inet_ntop(AF_INET, &ip_v4, ip_str, IP_STR_MAX_LENGTH);
	return(ip_str);
}

#ifdef CLOUD_ROUTER_CLIENT
std::string vmIP::getStringForMysqlIpColumn(const char *table, const char *column) const {
	return(_getStringForMysqlIpColumn(VM_IPV6_B && SqlDb::_isIPv6Column(table, column) ? 6 : 4));
}
#endif

std::string vmIP::_getStringForMysqlIpColumn(int IPv) const {
	return(IPv == 6 ?
		"inet6_aton('" + getString() + "')" :
		intToString(getIPv4()));
}

bool vmIP::isLocalIP() {
	const char *net_str[] = {
		"192.168.0.0/16",
		"10.0.0.0/8",
		"172.16.0.0/20"
	};
	static vmIP net[3];
	static vmIP net_mask[3];
	if(!net[0].isSet()) {
		for(int i = 0; i < 3; i++) {
			vector<string> ip_mask = split(net_str[i], "/", true);
			unsigned net_mask_bits = atoi(ip_mask[1].c_str());
			vmIP ip;
			ip.setFromString(ip_mask[0].c_str());
			net[i] = ip.network(net_mask_bits);
			net_mask[i] = ip.network_mask(net_mask_bits);
		}
	}
	for(int i = 0; i < 3; i++) {
		if(this->mask(net_mask[i]) == net[i]) {
			return(true);
		}
	}
	return(false);
}

#if VM_IPV6
u_int8_t ip6hdr2::get_ext_headers(u_int8_t *ext_headers_type, u_int8_t ext_headers_max, u_int8_t *ext_headers_count) {
	if(ext_headers_count) {
		*ext_headers_count = 0;
	}
	u_int8_t nxt = this->nxt;
	u_int16_t offset_ext_header = 0;
	while(is_ext_header(nxt)) {
		u_char *header = (u_char*)this + sizeof(ip6hdr2) + offset_ext_header;
		u_int16_t ext_header_size = get_ext_header_size(header, nxt);
		if(!ext_header_size) {
			return(-1);
		}
		if(ext_headers_type) {
			if(*ext_headers_count >= ext_headers_max) {
				return(-1);
			}
			ext_headers_type[*ext_headers_count] = nxt;
			++*ext_headers_count;
		}
		nxt = get_ext_header_nxt(header, nxt);
		offset_ext_header += ext_header_size;
	}
	return(nxt);
}

u_int16_t ip6hdr2::get_ext_headers_len(u_int8_t *proto) {
	u_int8_t ext_headers_type[IP6_EXT_HEADERS_MAX];
	u_int8_t ext_headers_count;
	u_int8_t nxt = get_ext_headers(ext_headers_type, sizeof(ext_headers_type) / sizeof(ext_headers_type[0]), &ext_headers_count);
	if(nxt == (u_int8_t)-1) {
		return(-1);
	}
	if(proto) {
		*proto = nxt;
	}
	u_int16_t size = 0;
	for(unsigned i = 0; i < ext_headers_count; i++) {
		size += get_ext_header_size((u_char*)this + sizeof(ip6hdr2) + size, ext_headers_type[i]);
	}
	return(size);
}

u_int16_t ip6hdr2::get_ext_header_offset(u_int8_t header_id) {
	u_int8_t ext_headers_type[IP6_EXT_HEADERS_MAX];
	u_int8_t ext_headers_count;
	u_int8_t nxt = get_ext_headers(ext_headers_type, sizeof(ext_headers_type) / sizeof(ext_headers_type[0]), &ext_headers_count);
	if(nxt == (u_int8_t)-1 || ext_headers_count == 0) {
		return(-1);
	}
	u_int16_t offset = sizeof(ip6hdr2);
	for(unsigned i = 0; i < ext_headers_count; i++) {
		if(ext_headers_type[i] == header_id) {
			return(offset);
		}
		offset += get_ext_header_size((u_char*)this + sizeof(ip6hdr2) + offset, ext_headers_type[i]);
	}
	return(-1);
}
#endif

std::string vmPort::getString() {
	return(intToString(port));
}


#ifdef CLOUD_ROUTER_CLIENT
vmIP mysql_ip_2_vmIP(void *row, const char *column) {
	vmIP ip;
	ip.setIP(row, column);
	return(ip);
}
#endif


void socket_set_saddr(sockaddr_in *addr, vmIP ip, vmPort port) {
	memset(addr, 0, sizeof(sockaddr_in));
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = ip.getIPv4(true);
	addr->sin_port = port.getPort(true);
}

#if VM_IPV6
void socket_set_saddr(sockaddr_in6 *addr, vmIP ip, vmPort port) {
	memset(addr, 0, sizeof(sockaddr_in6));
	addr->sin6_family = AF_INET6;
	addr->sin6_addr = ip.getIPv6(true);
	addr->sin6_port = port.getPort(true);
}
#endif

int socket_create(vmIP ip, int type, int protocol) {
	return(socket(
		      #if VM_IPV6
		      ip.is_v6() ? AF_INET6 :
		      #endif
		      AF_INET, 
		      type, protocol));
}

int socket_connect(int socket, vmIP ip, vmPort port) {
	#if VM_IPV6
	if(ip.is_v6()) {
		sockaddr_in6 addr;
		socket_set_saddr(&addr, ip, port);
		return(connect(socket, (sockaddr*)&addr, sizeof(addr)));
	} else {
	#endif
		sockaddr_in addr;
		socket_set_saddr(&addr, ip, port);
		return(connect(socket, (sockaddr*)&addr, sizeof(addr)));
	#if VM_IPV6
	}
	#endif
}

int socket_bind(int socket, vmIP ip, vmPort port) {
	#if VM_IPV6
	if(ip.is_v6()) {
		sockaddr_in6 addr;
		socket_set_saddr(&addr, ip, port);
		return(::bind(socket, (sockaddr*)&addr, sizeof(addr)));
	} else {
	#endif
		sockaddr_in addr;
		socket_set_saddr(&addr, ip, port);
		return(::bind(socket, (sockaddr*)&addr, sizeof(addr)));
	#if VM_IPV6
	}
	#endif
}

int socket_accept(int socket, vmIP *ip, vmPort *port) {
	unsigned addrLength =
	#if VM_IPV6
	sizeof(sockaddr_in6);
	#else
	sizeof(sockaddr_in);
	#endif
	u_char *addr = new u_char[addrLength];
	int rslt = accept(socket, (sockaddr*)addr, &addrLength);
	if(rslt >= 0) {
	#if VM_IPV6
	if(((sockaddr_in*)addr)->sin_family == AF_INET6) {
		if(ip) {
			ip->setIPv6(((sockaddr_in6*)addr)->sin6_addr, true);
		}
		if(port) {
			port->setPort(((sockaddr_in6*)addr)->sin6_port, true);
		}
	} else {
	#endif
		if(ip) {
			ip->setIPv4(((sockaddr_in*)addr)->sin_addr.s_addr, true);
		}
		if(port) {
			port->setPort(((sockaddr_in*)addr)->sin_port, true);
		}
	#if VM_IPV6
	}
	#endif
	}
	delete [] addr;
	return(rslt);
}
