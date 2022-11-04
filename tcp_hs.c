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
    char *data;
    size_t packetsize;
    char recvdata[1500];
    
    int sockfd;
    struct sockaddr_inet sockdst;
    int sockdst_len;

    src.s_addr = inet_addr("172.17.50.11");
    dst.s_addr = inet_addr("172.30.0.3");
    sport = gen_sport();
    dport = 80;

    /* create raw socket */
    sockfd = rsockfd(IPP_TCP);
    setsockaddr(&sockdst, dst, dport);

    /* set socket info */
    struct sockinfo socket;
    socket.fd       = sockfd;
    socket.src_addr = &src;
    socket.dst_addr = &dst;
    socket.src_port = sport;
    socket.dst_port = dport;
    socket.sockdst  = sockdst;

    /* tcp 3 way handshake */
    if (tcp_connect(&socket, recvdata) < 0) {
        fprintf(stderr, "Failed to establish connection.\n");
        return -1;
    }

    /* send data */
    data = "GET / HTTP/1.1\r\nHost: 172.30.0.3\r\n\r\n";
    tcp_send(&socket, recvdata, data);

    /* receive data */
    struct tcp_hdr *res;
    int ret;
    while (1) {
        ret = tcp_read(&socket, recvdata);

        res = cvt2tcp(recvdata);
        printf("%s", tcp_payload(res));

        if (ret != 0) {
            break;
        }
    }

    close(sockfd);
}
