#include <stdlib.h>
#include "ip_header.h"
#include "tcp_header.h"
#include "socket.h"
#include "packet.h"
#include "genrand.h"


void tcp_connect(int fd, struct inet_addr *src, struct inet_addr *dst, unsigned short sport, unsigned short dport,
                    struct sockaddr_inet *sockdst, char *buffer) {
    char    *ip_packet;
    size_t  packetsize;
    char    *data;          /* empty data */

    /* for recvfrom */
    int buffersize = 1500;
    int sockdst_len;

    /* create ipv4 header */
    data = "";
    packetsize = packet_size(IPP_TCP, data);
    ip_packet = pballoc(packetsize);
    set_ipv4(ip_packet, src, dst, IPP_TCP, packetsize);

    /* send TCP SYN */
    set_tcp(ip_packet, src, dst, sport, dport, htonl(gen_initseq()), 0, TCPF_SYN, 64240, 0, data);
    sendrsock(fd, ip_packet, packetsize, *sockdst);

    /* receive TCP SYN/ACK */
    recvrsock(fd, buffer, buffersize, 0, (struct sockaddr *)sockdst, &sockdst_len);
    
    /* casting receieved data to tcp data format */
    struct tcp_hdr *tcp = cvt2tcp(buffer);

    /* send TCP ACK */
    set_tcp(ip_packet, src, dst, sport, dport, tcp->th_ack, ntohl(htonl(tcp->th_seq) + 1), TCPF_ACK, 64240, 0, data);
    sendrsock(fd, ip_packet, packetsize, *sockdst);

    free(ip_packet);
}

void tcp_read(int fd, struct inet_addr *src, struct inet_addr *dst, unsigned short sport, unsigned short dport,
                    struct sockaddr_inet *sockdst, char *buffer) {
    char    *ip_packet;
    size_t  packetsize;
    char    *data;

    /* for recvfrom */
    int buffersize = 1500;
    int sockdst_len;

    /* receive data */
    recvrsock(fd, buffer, buffersize, 0, (struct sockaddr *)sockdst, &sockdst_len);

    /* compute tcp data length */
    struct tcp_hdr *tcp = cvt2tcp(buffer);
    size_t tcp_data_len = tcp_pl_len(buffer);

    data = "";
    packetsize = packet_size(IPP_TCP, data);
    ip_packet = pballoc(packetsize);
    set_ipv4(ip_packet, src, dst, IPP_TCP, packetsize);

    if (tcp->th_flags != TCPF_FIN + TCPF_ACK && tcp->th_flags != TCPF_FIN + TCPF_ACK + TCPF_PSH) {
        /* send TCP ACK (sequence num + received data len)*/
        set_tcp(ip_packet, src, dst, sport, dport, tcp->th_ack, ntohl(htonl(tcp->th_seq) + tcp_data_len), TCPF_ACK, 64240, 0, data);
        sendrsock(fd, ip_packet, packetsize, *sockdst);
    }
        
    free(ip_packet);
}

void tcp_close(int fd, struct inet_addr *src, struct inet_addr *dst, unsigned short sport, unsigned short dport,
                    struct sockaddr_inet *sockdst, char *buffer) {
    char    *ip_packet;
    size_t  packetsize;
    char    *data;

    data = "";
    packetsize = packet_size(IPP_TCP, data);
    ip_packet = pballoc(packetsize);
    set_ipv4(ip_packet, src, dst, IPP_TCP, packetsize);

    struct tcp_hdr *tcp = cvt2tcp(buffer);

    if (tcp->th_flags == TCPF_FIN + TCPF_ACK) {
        /* send TCP ACK */
        set_tcp(ip_packet, src, dst, sport, dport, tcp->th_ack, ntohl(htonl(tcp->th_seq) + 1), TCPF_ACK, 64240, 0, data);
        sendrsock(fd, ip_packet, packetsize, *sockdst);
        /* send TCP FIN/ACK */
        set_tcp(ip_packet, src, dst, sport, dport, tcp->th_ack, ntohl(htonl(tcp->th_seq) + 1), TCPF_FIN + TCPF_ACK, 64240, 0, data);
        sendrsock(fd, ip_packet, packetsize, *sockdst);
    }
    else if (tcp->th_flags == TCPF_FIN + TCPF_PSH + TCPF_ACK) {
        /* compute tcp data length */
        size_t tcp_data_len = tcp_pl_len(buffer);
        /* send TCP ACK */
        set_tcp(ip_packet, src, dst, sport, dport, tcp->th_ack, ntohl(htonl(tcp->th_seq) + tcp_data_len + 1), TCPF_ACK, 64240, 0, data);
        sendrsock(fd, ip_packet, packetsize, *sockdst);
        /* send TCP FIN/ACK */
        set_tcp(ip_packet, src, dst, sport, dport, tcp->th_ack, ntohl(htonl(tcp->th_seq) + 1), TCPF_FIN + TCPF_ACK, 64240, 0, data);
        sendrsock(fd, ip_packet, packetsize, *sockdst);
    }
    
    free(ip_packet);
}