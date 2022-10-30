/* for debug */
#include <stdio.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include "ip_header.h"
#include "udp_header.h"
#include "socket_struct.h"

/* computing checksum */
unsigned short in_cksum(unsigned short *addr, int len) {
    int nleft, sum;
    unsigned short *w;
    union {
        unsigned short us;
        unsigned char  uc[2];
    } last;
    unsigned short answer;

    nleft = len;
    sum = 0;
    w = addr;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
        last.uc[0] = *(unsigned char *)w;
        last.uc[1] = 0;
        sum += last.us;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
    sum += (sum >> 16);                     /* add carry */
    answer = ~sum;                          /* truncate to 16 bits */
    return(answer);
}


/* set IPv4 packet */
void set_ipv4(char *p, struct inet_addr *src, struct inet_addr *dst,
                unsigned short protocol, size_t len, char *data, size_t data_len) {
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

    /* set data after ipv4 header */
    memcpy(p + (ip->ip_hl << 2), data, data_len);
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
    /* computing checsum */
    udp->uh_sum = in_cksum((unsigned short *)buffer, total_len);

    /* retrun udp datagram */
    memcpy(p, udp, total_len - sizeof(struct ippseudo_hdr));

    free(buffer);
}

char *segalloc(unsigned short protocol, char *data) {
    char *buffer;
    switch (protocol) {
        case IPP_UDP:
            buffer = malloc(sizeof(struct udp_hdr) + strlen(data));
            break;
        case IPP_TCP:
            /* TODO */
            break;
        default:
            break;
    }
    if (buffer == NULL) {
        fprintf(stderr, "ERR: failed to allocate memory for segment.\n");
        exit(1);
    }
    return buffer;
}

int main(void) {
    int sock_d;
    char *data;
    char *udp_datagram, *ip_packet;
    struct inet_addr src, dst;
    unsigned short sport, dport;
    struct sockaddr_inet sock_to;
    socklen_t tolen = sizeof(struct sockaddr_inet);
    size_t packetsize, datagramsize;
    int on = 1;

    src.s_addr = inet_addr("192.168.1.1");
    dst.s_addr = inet_addr("172.30.0.3");
    sport = 65001;
    dport = 12345;
    data  = "This is test packet";

    datagramsize = sizeof(struct udp_hdr) + strlen(data);
    udp_datagram = segalloc(IPP_UDP, data);
    packetsize = sizeof(struct ip_hdr) + datagramsize;
    if ((ip_packet = malloc(packetsize)) == NULL) {
        fprintf(stderr, "ERR: failed to allocate memory for ip packet.\n");
        exit(1);
    }

    if ((sock_d = socket(PF_INET, SOCK_RAW, IPP_RAW)) < 0) {
        fprintf(stderr, "ERR: failed to create socket.\n");
        exit(1);
    }
    if (setsockopt(sock_d, IPP_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        fprintf(stderr, "ERR: failed to set socket option.\n");
        exit(1);
    }

    set_udp(udp_datagram, &src, &dst, sport, dport, data);
    set_ipv4(ip_packet, &src, &dst, IPP_UDP, packetsize, udp_datagram, datagramsize);

    memset(&sock_to, 0, sizeof(struct sockaddr_in));
    sock_to.sin_addr    = dst;
    sock_to.sin_port    = htons(dport);
    sock_to.sin_family  = AF_INET;

    printf("Sending data.\n");
    if (sendto(sock_d, ip_packet, packetsize, 0, (struct sockaddr *)&sock_to, tolen) < 0) {
        fprintf(stderr, "ERR: sendto failure.\n");
        exit(1);
    }

    free(udp_datagram);
    free(ip_packet);
    close(sock_d);
}