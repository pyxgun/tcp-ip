#include <stdlib.h>
#include "ip_header.h"
#include "tcp_header.h"
#include "socket.h"
#include "packet.h"
#include "genrand.h"

void tcp_connect(int fd, struct inet_addr *src, struct inet_addr *dst, unsigned short sport, unsigned short dport, struct sockaddr_inet *sockdst, char *buffer) {
    char    *ip_packet;
    size_t  packetsize;
    char    *data;          /* empty data */

    /* for recvfrom */
    int buffersize = 256;
    int sockdst_len;

    /* create ipv4 header */
    data = "";
    packetsize = packet_size(IPP_TCP, data);
    ip_packet = pballoc(packetsize);
    set_ipv4(ip_packet, src, dst, IPP_TCP, packetsize);

    /* send TCP SYN */
    set_tcp(ip_packet, src, dst, sport, dport, htonl(gen_initseq()), 0, TCPF_SYN, 64240, 0, data);
    sendrsock(fd, ip_packet, packetsize, *sockdst);

    /* receive TCP SYN/ACK */
    recvrsock(fd, buffer, buffersize, 0, (struct sockaddr *)sockdst, &sockdst_len);
    
    /* casting receieved data to tcp data format */
    struct ip_hdr *ip = (struct ip_hdr *)buffer;
    struct tcp_hdr *tcp = (struct tcp_hdr *)((char *)ip + (ip->ip_hl << 2));

    /* send TCP SYN */
    set_tcp(ip_packet, src, dst, sport, dport, tcp->th_ack, ntohl(htonl(tcp->th_seq) + 1), TCPF_ACK, 64240, 0, data);
    sendrsock(fd, ip_packet, packetsize, *sockdst);

    free(ip_packet);
}
