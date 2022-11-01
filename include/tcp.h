#ifndef _TCP_OPERATION
#define _TCP_OPERATION  1

#include "socket_struct.h"
#include "ip_header.h"

void tcp_connect(int fd, struct inet_addr *src, struct inet_addr *dst, unsigned short sport, unsigned short dport,
                    struct sockaddr_inet *sockdst, char *buffer);

void tcp_read(int fd, struct inet_addr *src, struct inet_addr *dst, unsigned short sport, unsigned short dport,
                    struct sockaddr_inet *sockdst, char *buffer);

void tcp_close(int fd, struct inet_addr *src, struct inet_addr *dst, unsigned short sport, unsigned short dport,
                    struct sockaddr_inet *sockdst, char *buffer);

#endif