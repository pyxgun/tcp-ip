#include <stdlib.h>
#include <unistd.h>

#include "ip_header.h"
#include "tcp_header.h"
#include "socket_struct.h"
#include "socket.h"
#include "packet.h"
#include "genrand.h"
#include "tcp.h"


int main(int argc, char **argv) {
    struct inet_addr src, dst;
    unsigned short sport, dport;
    char *data, *ip_packet, *tcp_packet;
    size_t packetsize;
    char recvdata[256];
    
    int sockfd;
    struct sockaddr_inet sockdst;

    src.s_addr = inet_addr("172.17.50.11");
    dst.s_addr = inet_addr("172.30.0.3");
    sport = gen_sport();
    dport = 80;

    /* create raw socket */
    sockfd = rsockfd(IPP_TCP);
    setsockaddr(&sockdst, dst, dport);

    /* tcp 3 way handshake */
    tcp_connect(sockfd, &src, &dst, sport, dport, &sockdst, recvdata);

    /* casting receieved data to tcp data format */
    struct ip_hdr *ip = (struct ip_hdr *)recvdata;
    struct tcp_hdr *tcp = (struct tcp_hdr *)((char *)ip + (ip->ip_hl << 2));

    /* send data */
    data = "GET / HTTP/1.1\r\nHost: 172.30.0.3:80\r\n\r\n";
    packetsize = packet_size(IPP_TCP, data);
    ip_packet = pballoc(packetsize);
    set_ipv4(ip_packet, &src, &dst, IPP_TCP, packetsize);
    set_tcp(ip_packet, &src, &dst, sport, dport, tcp->th_ack, ntohl(htonl(tcp->th_seq) + 1), TCPF_ACK, 64240, 0, data);
    sendrsock(sockfd, ip_packet, packetsize, sockdst);

    free(ip_packet);
    close(sockfd);
}
