#ifndef _SOCKET_FUNC
#define _SOCKET_FUNC 1

/* create raw socket file descriptor */
int rsockfd(unsigned short protocol);

/* set sockaddr_inet */
void setsockaddr(struct sockaddr_inet *sockaddr, struct inet_addr dst, in_port_t port);

/* send raw socket */
void sendrsock(int fd, char *data, size_t data_len, struct sockaddr_inet sockaddr);

/* receive raw socket */
void recvrsock(int fd, void *buffer, size_t buffer_len, int flag, struct sockaddr *addr, int *addr_len);

#endif