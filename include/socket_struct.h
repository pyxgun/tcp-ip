#ifndef _SOCKET_STRUCT
#define _SOCKET_STRUCT  1

#include <sys/socket.h>
#include <stdint.h>
#include "ip_header.h"

typedef uint16_t    in_port_t;

struct sockaddr_inet {
    sa_family_t      sin_family;
    in_port_t        sin_port;
    struct inet_addr sin_addr;

    /* pad to size of `struct sockaddr` */
    unsigned char sin_zero[sizeof(struct sockaddr)
                            - __SOCKADDR_COMMON_SIZE
                            - sizeof(in_port_t)
                            - sizeof(struct inet_addr)];
};

struct sockinfo {
    int                     fd;
    struct inet_addr        *src_addr;
    struct inet_addr        *dst_addr;
    unsigned short          src_port;
    unsigned short          dst_port;
    struct sockaddr_inet    sockdst;
};

#endif