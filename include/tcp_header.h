#ifndef _TCP_HEADER
#define _TCP_HEADER 1

#include <stdint.h>
#include <endian.h>

typedef uint32_t tcp_seq;

struct tcp_hdr {
    uint16_t    th_sport;       /* source port */
    uint16_t    th_dport;       /* destination port */
    tcp_seq     th_seq;         /* sequence number */
    tcp_seq     th_ack;         /* acknowledgement number */
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t     th_x2:4;        /* (unused) */
    uint8_t     th_off:4;       /* data offset */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t     th_off:4;       /* data offset */
    uint8_t     th_x2:4;        /* (unused) */
#endif
    uint8_t     th_flags;       /* flag */
#define TCPF_FIN    0x01
#define TCPF_SYN    0x02
#define TCPF_RST    0x04
#define TCPF_PSH    0x08
#define TCPF_ACK    0x10
#define TCPF_URG    0x20
    uint16_t    th_win;         /* window size */
    uint16_t    th_sum;         /* checksum */
    uint16_t    th_urp;         /* urgent pointer */
};

#define SOCKL_TCP   6           /* TCP level */

#define TCP_OPT_KEEPIDLE    4   /* start keeplives after this period */

#endif
