#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "ip_header.h"
#include "udp_header.h"
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
    sport = 65001;
    dport = 12233;

    data = "Hello World.\n";

    /* create ipv4 header and udp datagram */
    packetsize = packet_size(IPP_UDP, data);
    ip_packet = pballoc(packetsize);
    set_ipv4(ip_packet, &src, &dst, IPP_UDP, packetsize);
    set_udp(ip_packet, &src, &dst, sport, dport, data);

    /* create raw socket */
    sockfd = rsockfd();
    setsockaddr(&sockdst, dst, dport);

    /* send raw socket */
    sendrsock(sockfd, ip_packet, packetsize, sockdst);

    free(ip_packet);
    close(sockfd);
}
