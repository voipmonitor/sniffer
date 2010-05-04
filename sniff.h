void readdump(pcap_t *handle);

#if 1
struct iphdr {
#if defined(__LITTLE_ENDIAN)
        uint8_t ihl:4,
                version:4;
#elif defined (__BIG_ENDIAN)
        uint8_t version:4,
                ihl:4;
#elif
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

