// Simple DNS resolver for static binaries
// This implementation sends DNS queries directly to DNS servers
// avoiding the NSS layer that causes problems with static linking

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

// DNS protocol constants
#define DNS_PORT 53
#define DNS_BUFFER_SIZE 512
#define DNS_TYPE_A 1
#define DNS_TYPE_AAAA 28
#define DNS_CLASS_IN 1
#define DNS_TIMEOUT 5

// DNS header structure
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

// Simple cache structure
#define CACHE_SIZE 100
struct cache_entry {
    char hostname[256];
    struct in_addr addr;
    time_t expiry;
};

static struct cache_entry dns_cache[CACHE_SIZE];
static int cache_initialized = 0;

// Initialize cache
static void init_cache() {
    if (!cache_initialized) {
        memset(dns_cache, 0, sizeof(dns_cache));
        cache_initialized = 1;
    }
}

// Check cache for hostname
static int check_cache(const char *hostname, struct in_addr *addr) {
    init_cache();
    time_t now = time(NULL);
    
    for (int i = 0; i < CACHE_SIZE; i++) {
        if (dns_cache[i].hostname[0] && 
            strcmp(dns_cache[i].hostname, hostname) == 0 &&
            dns_cache[i].expiry > now) {
            *addr = dns_cache[i].addr;
            return 1;
        }
    }
    return 0;
}

// Add entry to cache
static void add_to_cache(const char *hostname, struct in_addr *addr) {
    init_cache();
    time_t now = time(NULL);
    
    // Find empty slot or oldest entry
    int oldest = 0;
    time_t oldest_time = dns_cache[0].expiry;
    
    for (int i = 0; i < CACHE_SIZE; i++) {
        if (dns_cache[i].hostname[0] == 0 || dns_cache[i].expiry <= now) {
            oldest = i;
            break;
        }
        if (dns_cache[i].expiry < oldest_time) {
            oldest = i;
            oldest_time = dns_cache[i].expiry;
        }
    }
    
    strncpy(dns_cache[oldest].hostname, hostname, 255);
    dns_cache[oldest].hostname[255] = 0;
    dns_cache[oldest].addr = *addr;
    dns_cache[oldest].expiry = now + 300; // 5 minute TTL
}

// Get DNS server from /etc/resolv.conf
static int get_dns_server(char *dns_server) {
    FILE *fp = fopen("/etc/resolv.conf", "r");
    if (!fp) {
        // Default to Google DNS if can't read resolv.conf
        strcpy(dns_server, "8.8.8.8");
        return 1;
    }
    
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "nameserver", 10) == 0) {
            char *p = line + 10;
            while (*p == ' ' || *p == '\t') p++;
            sscanf(p, "%s", dns_server);
            fclose(fp);
            return 1;
        }
    }
    
    fclose(fp);
    strcpy(dns_server, "8.8.8.8");
    return 1;
}

// Build DNS query
static int build_dns_query(uint8_t *buffer, const char *hostname, uint16_t query_id) {
    struct dns_header *header = (struct dns_header *)buffer;
    
    header->id = htons(query_id);
    header->flags = htons(0x0100); // Standard query, recursion desired
    header->qdcount = htons(1);
    header->ancount = 0;
    header->nscount = 0;
    header->arcount = 0;
    
    // Add question
    uint8_t *qname = buffer + sizeof(struct dns_header);
    const char *src = hostname;
    uint8_t *len_pos = qname;
    uint8_t len = 0;
    
    qname++;
    while (*src) {
        if (*src == '.') {
            *len_pos = len;
            len_pos = qname;
            len = 0;
            qname++;
            src++;
        } else {
            *qname = *src;
            qname++;
            src++;
            len++;
        }
    }
    *len_pos = len;
    *qname++ = 0; // End of domain name
    
    // Query type and class
    *(uint16_t *)qname = htons(DNS_TYPE_A);
    qname += 2;
    *(uint16_t *)qname = htons(DNS_CLASS_IN);
    qname += 2;
    
    return qname - buffer;
}

// Parse DNS response
static int parse_dns_response(uint8_t *buffer, int len, struct in_addr *addr) {
    if (len < sizeof(struct dns_header)) {
        return 0;
    }
    
    struct dns_header *header = (struct dns_header *)buffer;
    uint16_t ancount = ntohs(header->ancount);
    
    if (ancount == 0) {
        return 0;
    }
    
    // Skip the question section
    uint8_t *ptr = buffer + sizeof(struct dns_header);
    while (*ptr != 0 && ptr < buffer + len) {
        ptr++;
    }
    ptr++; // Skip null terminator
    ptr += 4; // Skip type and class
    
    // Parse answers
    for (int i = 0; i < ancount && ptr < buffer + len - 10; i++) {
        // Skip name (might be compressed)
        if ((*ptr & 0xC0) == 0xC0) {
            ptr += 2; // Compressed name
        } else {
            while (*ptr != 0 && ptr < buffer + len) {
                ptr++;
            }
            ptr++;
        }
        
        uint16_t type = ntohs(*(uint16_t *)ptr);
        ptr += 2;
        uint16_t class = ntohs(*(uint16_t *)ptr);
        ptr += 2;
        ptr += 4; // Skip TTL
        uint16_t rdlen = ntohs(*(uint16_t *)ptr);
        ptr += 2;
        
        if (type == DNS_TYPE_A && class == DNS_CLASS_IN && rdlen == 4) {
            memcpy(&addr->s_addr, ptr, 4);
            return 1;
        }
        
        ptr += rdlen;
    }
    
    return 0;
}

// Perform DNS lookup
static int dns_lookup(const char *hostname, struct in_addr *addr) {
    char dns_server[64];
    uint8_t query[DNS_BUFFER_SIZE];
    uint8_t response[DNS_BUFFER_SIZE];
    
    // Check cache first
    if (check_cache(hostname, addr)) {
        return 1;
    }
    
    // Get DNS server
    if (!get_dns_server(dns_server)) {
        return 0;
    }
    
    // Build query
    uint16_t query_id = (uint16_t)(time(NULL) & 0xFFFF);
    int query_len = build_dns_query(query, hostname, query_id);
    
    // Create socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return 0;
    }
    
    // Set timeout
    struct timeval tv;
    tv.tv_sec = DNS_TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    // Send query
    struct sockaddr_in dns_addr;
    memset(&dns_addr, 0, sizeof(dns_addr));
    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(DNS_PORT);
    inet_pton(AF_INET, dns_server, &dns_addr.sin_addr);
    
    if (sendto(sock, query, query_len, 0, 
               (struct sockaddr *)&dns_addr, sizeof(dns_addr)) < 0) {
        close(sock);
        return 0;
    }
    
    // Receive response
    socklen_t addr_len = sizeof(dns_addr);
    int response_len = recvfrom(sock, response, sizeof(response), 0,
                                (struct sockaddr *)&dns_addr, &addr_len);
    close(sock);
    
    if (response_len < 0) {
        return 0;
    }
    
    // Parse response
    if (parse_dns_response(response, response_len, addr)) {
        add_to_cache(hostname, addr);
        return 1;
    }
    
    return 0;
}

// Custom getaddrinfo implementation
int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints,
                struct addrinfo **res) {
    
    if (!node) {
        return EAI_NONAME;
    }
    
    // Handle localhost specially
    if (strcmp(node, "localhost") == 0) {
        struct addrinfo *ai = calloc(1, sizeof(struct addrinfo));
        struct sockaddr_in *sa = calloc(1, sizeof(struct sockaddr_in));
        
        sa->sin_family = AF_INET;
        sa->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (service) {
            sa->sin_port = htons(atoi(service));
        }
        
        ai->ai_family = AF_INET;
        ai->ai_socktype = hints ? hints->ai_socktype : SOCK_STREAM;
        ai->ai_protocol = hints ? hints->ai_protocol : 0;
        ai->ai_addrlen = sizeof(struct sockaddr_in);
        ai->ai_addr = (struct sockaddr *)sa;
        ai->ai_canonname = strdup("localhost");
        
        *res = ai;
        return 0;
    }
    
    // Try to parse as IP address first
    struct in_addr addr;
    if (inet_pton(AF_INET, node, &addr) == 1) {
        struct addrinfo *ai = calloc(1, sizeof(struct addrinfo));
        struct sockaddr_in *sa = calloc(1, sizeof(struct sockaddr_in));
        
        sa->sin_family = AF_INET;
        sa->sin_addr = addr;
        if (service) {
            sa->sin_port = htons(atoi(service));
        }
        
        ai->ai_family = AF_INET;
        ai->ai_socktype = hints ? hints->ai_socktype : SOCK_STREAM;
        ai->ai_protocol = hints ? hints->ai_protocol : 0;
        ai->ai_addrlen = sizeof(struct sockaddr_in);
        ai->ai_addr = (struct sockaddr *)sa;
        
        *res = ai;
        return 0;
    }
    
    // Perform DNS lookup
    if (dns_lookup(node, &addr)) {
        struct addrinfo *ai = calloc(1, sizeof(struct addrinfo));
        struct sockaddr_in *sa = calloc(1, sizeof(struct sockaddr_in));
        
        sa->sin_family = AF_INET;
        sa->sin_addr = addr;
        if (service) {
            sa->sin_port = htons(atoi(service));
        }
        
        ai->ai_family = AF_INET;
        ai->ai_socktype = hints ? hints->ai_socktype : SOCK_STREAM;
        ai->ai_protocol = hints ? hints->ai_protocol : 0;
        ai->ai_addrlen = sizeof(struct sockaddr_in);
        ai->ai_addr = (struct sockaddr *)sa;
        ai->ai_canonname = strdup(node);
        
        *res = ai;
        return 0;
    }
    
    return EAI_NONAME;
}

// Custom freeaddrinfo implementation
void freeaddrinfo(struct addrinfo *res) {
    while (res) {
        struct addrinfo *next = res->ai_next;
        if (res->ai_addr) {
            free(res->ai_addr);
        }
        if (res->ai_canonname) {
            free(res->ai_canonname);
        }
        free(res);
        res = next;
    }
}