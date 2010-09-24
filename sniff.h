/* Martin Vit support@voipmonitor.org
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2.
*/

void readdump(pcap_t *handle);

/* this is copied from libpcap sll.h header file, which is not included in debian distribution */
#define SLL_ADDRLEN       8               /* length of address field */
struct sll_header {
	u_int16_t sll_pkttype;          /* packet type */
	u_int16_t sll_hatype;           /* link-layer address type */
	u_int16_t sll_halen;            /* link-layer address length */
	u_int8_t sll_addr[SLL_ADDRLEN]; /* link-layer address */
	u_int16_t sll_protocol;         /* protocol */
};

#if 1
struct iphdr {
#if defined(__LITTLE_ENDIAN)
        uint8_t ihl:4,
                version:4;
#elif defined (__BIG_ENDIAN)
        uint8_t version:4,
                ihl:4;
#else
#error Endian not defined
#endif
        uint8_t tos;
        uint16_t        tot_len;
        uint16_t        id;
        uint16_t        frag_off;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t        check;
        uint32_t        saddr;
        uint32_t        daddr;
        /*The options start here. */
};

#endif
struct udphdr {
        uint16_t        source;
        uint16_t        dest;
        uint16_t        len;
        uint16_t        check;
};

