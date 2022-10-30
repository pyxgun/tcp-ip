#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include "socket_struct.h"
#include "ip_header.h"
#include "tcp_header.h"


int rsockfd(unsigned short protocol) {
    int fd;
    int optval = 1;     /* for socket option */

    /* create raw socket file descriptor */
    if ((fd = socket(AF_INET, SOCK_RAW, protocol)) < 0) {
        fprintf(stderr, "ERR: failed to create raw socket file descriptor.\n");
        exit(1);
    }
    /* set socket option for including ip header in raw socket */
    if (setsockopt(fd, IPP_IP, IP_HDRINCL, &optval, sizeof(optval)) < 0) {
        fprintf(stderr, "ERR: failed to set socket option.\n");
        exit(1);
    }

    if (protocol == IPP_TCP) {
        int opt = 5;
        if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0) {
            fprintf(stderr, "ERR: failed to set sokcet option: SO_KEEPALIVE.\n");
            exit(1);
        }
    }

    return fd;
}

void setsockaddr(struct sockaddr_inet *sockaddr, struct inet_addr dst, in_port_t port) {
    memset(sockaddr, 0, sizeof(struct sockaddr_inet));
    sockaddr->sin_addr   = dst;
    sockaddr->sin_port   = port;
    sockaddr->sin_family = AF_INET;
}

void sendrsock(int fd, char *data, size_t data_len, struct sockaddr_inet sockaddr) {
    if (sendto(fd, data, data_len, 0, (struct sockaddr *)&sockaddr, sizeof(struct sockaddr_inet)) < 0) {
        fprintf(stderr, "ERR: failed to send data.\n");
        exit(1);
    }
}

void recvrsock(int fd, void *buffer, size_t buffer_len, int flag, struct sockaddr *addr, socklen_t *addr_len) {
    if (recvfrom(fd, buffer, buffer_len, flag, addr, addr_len) < 0) {
        fprintf(stderr, "ERR: failed to receive data.\n");
        exit(1);
    }
}
