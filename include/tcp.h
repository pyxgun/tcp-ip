#ifndef _TCP_OPERATION
#define _TCP_OPERATION  1

#include "socket_struct.h"
#include "ip_header.h"

int tcp_connect(struct sockinfo *socket, char *buffer);

void tcp_close(struct sockinfo *socket, char *buffer);

int tcp_read(struct sockinfo *socket, char *buffer);

int tcp_send(struct sockinfo *socket, char *buffer, char *data, size_t len);

int tcp_syn(struct sockinfo *socket, char *buffer);

#endif