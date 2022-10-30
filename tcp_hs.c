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

    src.s_addr = inet_addr("172.17.50.11");
    dst.s_addr = inet_addr("172.30.0.3");
    sport = 65015;
    dport = 443;

    data = "";

    /* create ipv4 header and tcp datagram */
    packetsize = packet_size(IPP_TCP, data);
    ip_packet = pballoc(packetsize);
    set_ipv4(ip_packet, &src, &dst, IPP_TCP, packetsize);
    set_tcp(ip_packet, &src, &dst, sport, dport, 5174, 0, TCPF_SYN, 64240, 0, data);

    /* create raw socket */
    sockfd = rsockfd();
    setsockaddr(&sockdst, dst, dport);

    /* send raw socket */
    sendrsock(sockfd, ip_packet, packetsize, sockdst);

    int sockdst_len = sizeof(sockdst);
    char data_received[256];

    if (recvfrom(sockfd, data_received, sizeof(data_received), 0, (struct sockaddr*)&sockdst, &sockdst_len) < 0) {
        close(sockfd);
        free(ip_packet);
        exit(1);
    }

    close(sockfd);
    free(ip_packet);
}
