#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include "ip_header.h"
#include "udp_header.h"
#include "tcp_header.h"

/* computing checksum */
unsigned short in_cksum(unsigned short *buff, int len) {
    unsigned long cksum = 0;
    while (len > 1) {
        cksum += *buff++;
        len -= 2;
    }
    if (len) {
        cksum += *(uint8_t *)buff;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum = (cksum >> 16) + (cksum & 0xffff);
    return (unsigned short)(~cksum);
}


size_t packet_size(unsigned short protocol, char *data) {
    size_t packetsize;
    
    /* payload size */
    switch (protocol) {
        case IPP_UDP:
            packetsize = sizeof(struct udp_hdr);
            break;
        case IPP_TCP:
            packetsize = sizeof(struct tcp_hdr);
            break;
    }
    /* ip header and payload size */
    packetsize += sizeof(struct ip_hdr) + strlen(data);

    return packetsize;
}

char *pballoc(size_t packet_size) {
    char *buffer = malloc(packet_size);
    return buffer;
}


/* set IPv4 packet */
void set_ipv4(char *p, struct inet_addr *src, struct inet_addr *dst, unsigned short protocol, size_t len) {
    struct ip_hdr *ip;

    ip = (struct ip_hdr *)p;
    ip->ip_v    = IPVERSION;        /* IPv4 */
    ip->ip_hl   = 5;                /* IPv4 header length without ip option */
    ip->ip_tos  = 1;                /* type of service */
    ip->ip_len  = len;              /* total length */
    ip->ip_id   = htons(getpid());  /* identification */
    ip->ip_off  = 0;                /* dont fragments */
    ip->ip_ttl  = IPDEFTTL;         /* time to live */
    ip->ip_p    = protocol;         /* ip protocol */
    ip->ip_sum  = 0;                /* initiate checksum */
    ip->ip_src  = *src;             /* source address */
    ip->ip_dst  = *dst;             /* destination address */
    /* computing checksum */
    ip->ip_sum  = in_cksum((unsigned short *)ip, ip->ip_hl << 2);
}

struct ip_hdr *cvt2ipv4(char *p) {
    return (struct ip_hdr *)p;
}


void set_udp(char *p, struct inet_addr *src, struct inet_addr *dst,
                unsigned short sport, unsigned short dport, char *data) {
    char *buffer;
    struct ip_hdr *ip;
    struct udp_hdr *udp;
    struct ippseudo_hdr *pse;
    int total_len;

    /* computing total size of pseudo header, udp header and payload */
    total_len = sizeof(struct ippseudo_hdr) + sizeof(struct udp_hdr) + strlen(data);
    if ((buffer = malloc(total_len)) == NULL) {
        fprintf(stderr, "ERR: failed to allocate memory for udp header.\n");
        exit(1);
    }
    memset(buffer, 0, total_len);

    /* set pseudo header */
    pse = (struct ippseudo_hdr *)buffer;
    pse->ippseudo_src.s_addr = src->s_addr;
    pse->ippseudo_dst.s_addr = dst->s_addr;
    pse->ippseudo_p          = IPP_UDP;
    pse->ippseudo_len        = htons(sizeof(struct udp_hdr) + strlen(data));

    /* set udp header after pseudo header */
    udp = (struct udp_hdr *)(buffer + sizeof(struct ippseudo_hdr));
    udp->uh_sport = htons(sport);
    udp->uh_dport = htons(dport);
    udp->uh_ulen  = pse->ippseudo_len;
    udp->uh_sum   = 0;
    /* set data after udp header */
    memcpy((char *)udp + sizeof(struct udp_hdr), data, strlen(data));
    /* computing checksum */
    udp->uh_sum = in_cksum((unsigned short *)buffer, total_len);

    /* set udp datagram */
    ip = (struct ip_hdr *)p;
    memcpy(p + (ip->ip_hl << 2), udp, total_len - sizeof(struct ippseudo_hdr));

    free(buffer);
}

void set_tcp(char *p, struct inet_addr *src, struct inet_addr *dst, unsigned short sport, unsigned short dport,
                tcp_seq seq, tcp_seq ack, uint8_t flag, uint16_t win_size, uint16_t urp, char *data) {
    char *buffer;
    struct ip_hdr *ip;
    struct tcp_hdr *tcp;
    struct ippseudo_hdr *pse;
    int total_len;

    /* computing total size of pseudo header, tcp header and payload */
    total_len = sizeof(struct ippseudo_hdr) + sizeof(struct tcp_hdr) + strlen(data);
    if ((buffer = malloc(total_len)) == NULL) {
        fprintf(stderr, "ERR: failed to allocate memory for tcp header.\n");
        exit(1);
    }
    memset(buffer, 0, total_len);

    /* set pseudo header */
    pse = (struct ippseudo_hdr *)buffer;
    pse->ippseudo_src.s_addr = src->s_addr;
    pse->ippseudo_dst.s_addr = dst->s_addr;
    pse->ippseudo_p          = IPP_TCP;
    pse->ippseudo_len        = htons(sizeof(struct tcp_hdr) + strlen(data));

    /* set tcp header after pseudo header */
    tcp = (struct tcp_hdr *)(buffer + sizeof(struct ippseudo_hdr));
    tcp->th_sport   = htons(sport);
    tcp->th_dport   = htons(dport);
    tcp->th_seq     = seq;
    tcp->th_ack     = ack;
    tcp->th_off     = 5;
    tcp->th_x2      = 0;
    tcp->th_flags   = flag;
    tcp->th_win     = htons(win_size);
    tcp->th_sum     = 0;
    tcp->th_urp     = urp;
    /* set data after tcp header */
    if (strlen(data) != 0) {
        memcpy((char *)tcp + sizeof(struct tcp_hdr), data, strlen(data));
    }
    /* computing checksum */
    tcp->th_sum = in_cksum((unsigned short *)buffer, total_len);

    /* set udp datagram */
    ip = (struct ip_hdr *)p;
    memcpy(p + (ip->ip_hl << 2), tcp, total_len - sizeof(struct ippseudo_hdr));

    free(buffer);
}

struct tcp_hdr *cvt2tcp(char *p) {
    struct ip_hdr *ip = (struct ip_hdr *)p;
    return (struct tcp_hdr *)((char *)ip + (ip->ip_hl << 2));
}

char *tcp_payload(struct tcp_hdr *p) {
    return (char *)((char *)p + (p->th_off << 2));
}

size_t tcp_pl_len(char *p) {
    struct ip_hdr *ip = cvt2ipv4(p);
    struct tcp_hdr *tcp = cvt2tcp(p);
    size_t tcp_pl_len = htons(ip->ip_len) - (ip->ip_hl * 4) - (tcp->th_off * 4);
    return tcp_pl_len;
}