#include <stdlib.h>
#include <string.h>
#include "ip_header.h"
#include "tcp_header.h"
#include "socket_struct.h"
#include "socket.h"
#include "packet.h"
#include "genrand.h"

#include <stdio.h>

int tcp_connect(struct sockinfo *socket, char *buffer) {
    char    *ip_packet;
    size_t  packetsize;

    /* for recvfrom */
    int buffersize = 1500;
    int sockdst_len;

    /* create ipv4 header */
    packetsize = packet_size(IPP_TCP, "", 0);
    ip_packet = pballoc(packetsize);
    set_ipv4(ip_packet, socket->src_addr, socket->dst_addr, IPP_TCP, packetsize);

    /* send TCP SYN */
    set_tcp(ip_packet, socket->src_addr, socket->dst_addr, socket->src_port, socket->dst_port,
            htonl(gen_initseq()), 0, TCPF_SYN, 64240, 0, "", 0);
    sendrsock(socket->fd, ip_packet, packetsize, socket->sockdst);

    /* receive TCP SYN/ACK */
    if (recvrsock(socket->fd, buffer, buffersize, 0, (struct sockaddr *)&socket->sockdst, &sockdst_len) < 0) {
        free(ip_packet);
        return -1;
    }

    /* casting receieved data to tcp data format */
    struct tcp_hdr *tcp = cvt2tcp(buffer);

    switch (tcp->th_flags) {
        case TCPF_SYN + TCPF_ACK:
            /* send TCP ACK */
            set_tcp(ip_packet, socket->src_addr, socket->dst_addr, socket->src_port, socket->dst_port,
                    tcp->th_ack, ntohl(htonl(tcp->th_seq) + 1), TCPF_ACK, 64240, 0, "", 0);
            sendrsock(socket->fd, ip_packet, packetsize, socket->sockdst);
            free(ip_packet);
            break;
        default:
            free(ip_packet);
            return -1;
    }

    return 0;
}

void tcp_close(struct sockinfo *socket, char *buffer) {
    char    *ip_packet;
    size_t  packetsize;
    char    *data;
    int buffersize = 1500;
    int sockdst_len;

    packetsize = packet_size(IPP_TCP, "", 0);
    ip_packet = pballoc(packetsize);
    set_ipv4(ip_packet, socket->src_addr, socket->dst_addr, IPP_TCP, packetsize);

    struct tcp_hdr *tcp = cvt2tcp(buffer);

    switch (tcp->th_flags) {
        case TCPF_FIN + TCPF_ACK:
            /* send TCP ACK */
            set_tcp(ip_packet, socket->src_addr, socket->dst_addr, socket->src_port, socket->dst_port,
                    tcp->th_ack, ntohl(htonl(tcp->th_seq) + 1), TCPF_ACK, 64240, 0, data, 0);
            sendrsock(socket->fd, ip_packet, packetsize, socket->sockdst);
            /* send TCP FIN/ACK */
            set_tcp(ip_packet, socket->src_addr, socket->dst_addr, socket->src_port, socket->dst_port,
                    tcp->th_ack, ntohl(htonl(tcp->th_seq) + 1), TCPF_FIN + TCPF_ACK, 64240, 0, data, 0);
            sendrsock(socket->fd, ip_packet, packetsize, socket->sockdst);
            break;

        case TCPF_FIN + TCPF_PSH + TCPF_ACK:
            /* compute tcp data length */
            size_t tcp_data_len = tcp_pl_len(buffer);
            /* send TCP ACK */
            set_tcp(ip_packet, socket->src_addr, socket->dst_addr, socket->src_port, socket->dst_port,
                    tcp->th_ack, ntohl(htonl(tcp->th_seq) + tcp_data_len + 1), TCPF_ACK, 64240, 0, data, 0);
            sendrsock(socket->fd, ip_packet, packetsize, socket->sockdst);
            /* send TCP FIN/ACK */
            set_tcp(ip_packet, socket->src_addr, socket->dst_addr, socket->src_port, socket->dst_port,
                    tcp->th_ack, ntohl(htonl(tcp->th_seq) + 1), TCPF_FIN + TCPF_ACK, 64240, 0, data, 0);
            sendrsock(socket->fd, ip_packet, packetsize, socket->sockdst);
            break;

        default:
            set_tcp(ip_packet, socket->src_addr, socket->dst_addr, socket->src_port, socket->dst_port,
                    tcp->th_ack, ntohl(htonl(tcp->th_seq) + 1), TCPF_FIN + TCPF_ACK, 64240, 0, data, 0);
            sendrsock(socket->fd, ip_packet, packetsize, socket->sockdst);
            recvrsock(socket->fd, buffer, buffersize, 0, (struct sockaddr *)&socket->sockdst, &sockdst_len);
            tcp = cvt2tcp(buffer);
            set_tcp(ip_packet, socket->src_addr, socket->dst_addr, socket->src_port, socket->dst_port,
                    tcp->th_ack, ntohl(htonl(tcp->th_seq) + 1), TCPF_ACK, 64240, 0, data, 0);
            sendrsock(socket->fd, ip_packet, packetsize, socket->sockdst);
            break;
    }
    
    free(ip_packet);
}

int tcp_send(struct sockinfo *socket, char *buffer, char *data, size_t len) {
    struct tcp_hdr *tcp = cvt2tcp(buffer);
    char    *ip_packet;
    size_t  packetsize;

    /* for recvfrom */
    int buffersize = 1500;
    int sockdst_len;

    /* create ipv4 header */
    packetsize = packet_size(IPP_TCP, data, len);
    ip_packet = pballoc(packetsize);
    set_ipv4(ip_packet, socket->src_addr, socket->dst_addr, IPP_TCP, packetsize);
    /* TODO: implement TCP retransmission */
    /* send TCP SYN */
    set_tcp(ip_packet, socket->src_addr, socket->dst_addr, socket->src_port, socket->dst_port,
            tcp->th_ack, ntohl(htonl(tcp->th_seq) + 1), TCPF_ACK, 64240, 0, data, len);
    sendrsock(socket->fd, ip_packet, packetsize, socket->sockdst);

    memset(buffer, 0, buffersize);
    /* wait TCP ACK */
    if (recvrsock(socket->fd, buffer, buffersize, 0, (struct sockaddr *)&socket->sockdst, &sockdst_len) < 0) {
        free(ip_packet);
        return -1;
    }

    free(ip_packet);
    return 0;
}

int tcp_read(struct sockinfo *socket, char *buffer) {
    char    *ip_packet;
    size_t  packetsize;
    char    *data;

    /* for recvfrom */
    int buffersize = 1500;
    int sockdst_len;
    char prevdata[buffersize];
    memcpy(prevdata, buffer, buffersize);
    struct tcp_hdr *prevtcp = cvt2tcp(prevdata);

    int cnt = 0;
    while (1) {
        /* receive data */
        memset(buffer, 0, buffersize);
        if(recvrsock(socket->fd, buffer, buffersize, 0, (struct sockaddr *)&socket->sockdst, &sockdst_len) < 0) {
            tcp_close(socket, prevdata);
            return 1;
        }

        /* compute tcp data length */
        struct tcp_hdr *tcp = cvt2tcp(buffer);

        if (tcp->th_ack == prevtcp->th_ack) {
            switch (tcp->th_flags) {
                case TCPF_ACK:
                case TCPF_ACK + TCPF_PSH:
                    size_t tcp_data_len = tcp_pl_len(buffer);
                    packetsize = packet_size(IPP_TCP, "", 0);
                    ip_packet = pballoc(packetsize);
                    set_ipv4(ip_packet, socket->src_addr, socket->dst_addr, IPP_TCP, packetsize);

                    /* send TCP ACK (sequence num + received data len)*/
                    set_tcp(ip_packet, socket->src_addr, socket->dst_addr, socket->src_port, socket->dst_port,
                            tcp->th_ack, ntohl(htonl(tcp->th_seq) + tcp_data_len), TCPF_ACK, 64240, 0, data, 0);
                    sendrsock(socket->fd, ip_packet, packetsize, socket->sockdst);
                    free(ip_packet);
                    return 0;

                case TCPF_FIN:
                case TCPF_FIN + TCPF_ACK:
                case TCPF_FIN + TCPF_ACK + TCPF_PSH:
                    tcp_close(socket, buffer);
                    return 1;
            }
        }
    }
}
