#ifndef _UDP_HEADER
#define _UDP_HEADER 1

#include <stdint.h>

struct udp_hdr {
    uint16_t uh_sport;      /* source port */
    uint16_t uh_dport;      /* destination port */
    uint16_t uh_ulen;       /* udp length */
    uint16_t uh_sum;        /* checksum */
};

#endif