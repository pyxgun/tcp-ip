#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "ip_header.h"
#include "tcp_header.h"
#include "socket_struct.h"
#include "socket.h"
#include "packet.h"


int main(int argc, char **argv) {
    struct inet_addr src, dst;
    unsigned short sport, dport;
    char *data, *ip_packet;
    size_t packetsize;
    
    int sockfd;
    struct sockaddr_inet sockdst;

    /* for recvfrom */
    int sockdst_len;
    char data_received[256];

    src.s_addr = inet_addr("172.17.50.11");
    dst.s_addr = inet_addr("172.30.0.3");
    sport = 65154;
    dport = 11111;

    /* create ipv4 header */
    data = "";
    packetsize = packet_size(IPP_TCP, data);
    ip_packet = pballoc(packetsize);
    set_ipv4(ip_packet, &src, &dst, IPP_TCP, packetsize);

    /* create raw socket */
    sockfd = rsockfd(IPP_TCP);
    setsockaddr(&sockdst, dst, dport);

    /* send TCP SYN */
    set_tcp(ip_packet, &src, &dst, sport, dport, htonl(52380), 0, TCPF_SYN, 64240, 0, data);
    sendrsock(sockfd, ip_packet, packetsize, sockdst);

    /* receive raw socket */
    recvrsock(sockfd, &data_received, sizeof(data_received), 0, (struct sockaddr *)&sockdst, &sockdst_len);

    /* send TCP ACK */
    struct ip_hdr *ip = (struct ip_hdr *)data_received;
    struct tcp_hdr *tcp = (struct tcp_hdr *)((char *)ip + (ip->ip_hl << 2));
    set_tcp(ip_packet, &src, &dst, sport, dport, tcp->th_ack, ntohl(htonl(tcp->th_seq) + 1), TCPF_ACK, 64240, 0, data);
    sendrsock(sockfd, ip_packet, packetsize, sockdst);


    close(sockfd);
    free(ip_packet);
}
