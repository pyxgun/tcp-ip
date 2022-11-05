#ifndef _PACKET_FUNC
#define _PACKET_FUNC 1

#include "socket_struct.h"
#include "ip_header.h"
#include "tcp_header.h"

/* computing checksum */
unsigned short in_cksum(unsigned short *addr, int len);

/* calculate total packet size */
size_t packet_size(unsigned short protocol, char *data);

/* allocate memory for packet buffer */
char *pballoc(size_t packet_size);

/* set ipv4 header */
void set_ipv4(char *p, struct inet_addr *src, struct inet_addr *dst,
                unsigned short protocol, size_t len);

/* convert to ip header */
struct ip_hdr *cvt2ipv4(char *p);

/* set udp datagram */
void set_udp(char *p, struct inet_addr *src, struct inet_addr *dst,
                unsigned short sport, unsigned short dport, char *data);

/* set tcp datagram */
void set_tcp(char *p, struct inet_addr *src, struct inet_addr *dst, unsigned short sport, unsigned short dport,
                tcp_seq seq, tcp_seq ack, uint8_t flag, uint16_t win_size, uint16_t urp, char *data, size_t len);

/* convert to tcp header */
struct tcp_hdr *cvt2tcp(char *p);

/* retrieve tcp payload */
char *tcp_payload(struct tcp_hdr *p);

/* get tcp payload length */
size_t tcp_pl_len(char *p);

#endif