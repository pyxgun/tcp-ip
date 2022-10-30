#ifndef _TCP_HEADER
#define _TCP_HEADER 1

#include <stdint.h>
#include <endian.h>

typedef uint32_t tcp_seq;

struct tcp_hdr {
    uint16_t    th_sport;
    uint16_t    th_dport;
    tcp_seq     th_seq;
    tcp_seq     th_ack;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t     th_x2:4;
    uint8_t     th_off:4;
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t     th_off:4;
    uint8_t     th_x2:4;
#endif
    uint8_t     th_flags;
#define TCPF_FIN    0x01
#define TCPF_SYN    0x02
#define TCPF_RST    0x04
#define TCPF_PSH    0x08
#define TCPF_ACK    0x10
#define TCPF_URG    0x20
    uint16_t    th_win;
    uint16_t    th_sum;
    uint16_t    th_urp;
};

#endif