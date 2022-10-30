#ifndef _SOCKET_FUNC
#define _SOCKET_FUNC 1

/* create raw socket file descriptor */
int rsockfd(void);

/* set sockaddr_inet */
void setsockaddr(struct sockaddr_inet *sockaddr, struct inet_addr dst, in_port_t port);

/* send raw socket */
void sendrsock(int fd, char *data, size_t data_len, struct sockaddr_inet sockaddr);

#endif