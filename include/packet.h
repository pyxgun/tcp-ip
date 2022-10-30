#ifndef _PACKET_FUNC
#define _PACKET_FUNC 1

/* computing checksum */
unsigned short in_cksum(unsigned short *addr, int len);

/* set ipv4 header */
void set_ipv4(char *p, struct inet_addr *src, struct inet_addr *dst,
                unsigned short protocol, size_t len);

/* set udp datagram */
void set_udp(char *p, struct inet_addr *src, struct inet_addr *dst,
                unsigned short sport, unsigned short dport, char *data);

/* calculate total packet size */
size_t packet_size(unsigned short protocol, char *data);

/* allocate memory for packet buffer */
char *pballoc(size_t packet_size);

#endif