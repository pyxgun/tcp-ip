#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

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
    char recvdata[2048];
    
    int sockfd;
    struct sockaddr_inet sockdst;
    int sockdst_len;

    src.s_addr = inet_addr("172.17.50.11");
    dst.s_addr = inet_addr("172.30.0.3");
    sport = gen_sport();
    dport = 8888;

    /* create raw socket */
    sockfd = rsockfd(IPP_TCP);
    setsockaddr(&sockdst, dst, dport);

    /* tcp 3 way handshake */
    tcp_connect(sockfd, &src, &dst, sport, dport, &sockdst, recvdata);

    /* casting receieved data to tcp data format */
    struct tcp_hdr *tcp = cvt2tcp(recvdata);

    /* send data */
    data = "GET / HTTP/1.1\r\nHost: 172.30.0.3:8888\r\n\r\n";
    packetsize = packet_size(IPP_TCP, data);
    ip_packet = pballoc(packetsize);
    set_ipv4(ip_packet, &src, &dst, IPP_TCP, packetsize);
    set_tcp(ip_packet, &src, &dst, sport, dport, tcp->th_ack, ntohl(htonl(tcp->th_seq) + 1), TCPF_ACK, 64240, 0, data);
    sendrsock(sockfd, ip_packet, packetsize, sockdst);

    memset(recvdata, 0, 2048);
    recvrsock(sockfd, recvdata, 2048, 0, (struct sockaddr *)&sockdst, &sockdst_len);

    /* receive data */
    while (1) {
        memset(recvdata, 0, 2048);
        tcp_read(sockfd, &src, &dst, sport, dport, &sockdst, recvdata);

        struct tcp_hdr *res = cvt2tcp(recvdata);
        printf("%s", tcp_payload(res));

        /* close TCP connection */
        if (res->th_flags == TCPF_FIN + TCPF_ACK || res->th_flags == TCPF_FIN + TCPF_PSH + TCPF_ACK) {
            tcp_close(sockfd, &src, &dst, sport, dport, &sockdst, recvdata);
            break;
        }
    }

    free(ip_packet);
    close(sockfd);
}
