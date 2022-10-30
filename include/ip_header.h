#ifndef _IP_HEADER
#define _IP_HEADER  1

#include <sys/types.h>
#include <stdint.h>
#include <endian.h>

/* internet address */
typedef uint32_t in_addr_t;
struct inet_addr {
    in_addr_t s_addr;
};

/* structure of an ip header */
struct ip_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;       /* header length */
    unsigned int ip_v:4;        /* ip version */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;        /* ip version */
    unsigned int ip_hl:4;       /* header length */
#endif
    uint8_t          ip_tos;             /* type of service */
    unsigned short   ip_len;             /* total length */
    unsigned short   ip_id;              /* identification */
    unsigned short   ip_off;             /* fragment offset field */
#define IP_RF        0x8000              /* reserved fragment flag */
#define IP_DF        0x4000              /* dont fragment flag */
#define IP_MF        0x2000              /* more fragments flag */
#define IP_OFFMASK   0x1fff              /* mask for fragmenting bits */
    uint8_t          ip_ttl;             /* time to live */
    uint8_t          ip_p;               /* protocol */
    unsigned short   ip_sum;             /* checksum */
    struct inet_addr ip_src, ip_dst;     /* source and destination address */
};

/* 
 * This is the real IPv4 pseudo header, used for computing the TCP and UDP checksums.
 * for the internet checksum, struct ipovly can be used instead.
 * for stronger checksums, the real thing must be used.
 */
struct ippseudo_hdr {
    struct inet_addr    ippseudo_src;   /* source address */
    struct inet_addr    ippseudo_dst;   /* destination address */
    u_char              ippseudo_pad;   /* pad, must be zero */
    u_char              ippseudo_p;     /* protocol */
    u_short             ippseudo_len;   /* length */
};

#define IPVERSION   4       /* IP version number */

/* internet implementation parameters */
#define MAXTTL      255     /* maximum time to live */
#define IPDEFTTL    64      /* default ttl (RFC 1340) */
#define IPFRAGTTL   60      /* time to live for frags */
#define IPTTLDEC    1       /* subtracted when forwarding */


/* standard well-defined IP protocol */
enum {
    IPP_IP      = 0,        /* dummy */
#define IPP_IP      IPP_IP
    IPP_ICMP    = 1,        /* Internet Control Message Protocol */
#define IPP_ICMP    IPP_ICMP
    IPP_IGMP    = 2,        /* Internet Group Management Protocol */
#define IPP_IGMP    IPP_IGMP
    IPP_IPIP    = 4,        /* IPIP tunnels */
#define IPP_IPIP    IPP_IPIP
    IPP_TCP     = 6,        /* Transmission Control Protocol */
#define IPP_TCP     IPP_TCP
    IPP_UDP     = 17,       /* User Datagram Protocol */
#define IPP_UDP     IPP_UDP
    IPP_ESP     = 50,       /* Encapsulating Security Payload */
#define IPP_ESP     IPP_ESP
    IPP_AH      = 51,       /* Authentication Header */
#define IPP_AH      IPP_AH
    IPP_RAW     = 255,      /* raw IP packet */
#define IPP_RAW     IPP_RAW
};
#endif