//
// Created by barak on 25/12/2021.
//

// IPv4 header len without options
#define IP4_HDRLEN 20

// ICMP header len for echo req
#define ICMP_HDRLEN 8

#include <stdio.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include <unistd.h>

unsigned short calculate_checksum(unsigned short *p_address, int len);


#define SOURCE_IP "192.168.1.18"
// i.e the gateway or ping to google.com for their ip-address
#define DESTINATION_IP "192.168.1.1"

int main() {

    struct icmp icmphdr;
    char data[IP_MAXPACKET] = "This is the ping.\n";

    int datalen = strlen(data) + 1;


    //===================
    // ICMP header
    //===================

    // define Message Type -> ICMP_ECHO_REQUEST
    icmphdr.icmp_type = ICMP_ECHO;

    // define Message Code -> Echo Request
    icmphdr.icmp_code = 0;

    // Identifier id to trace the response.
    icmphdr.icmp_id = 18;

    // Sequence Number -> starts at 0.
    icmphdr.icmp_seq = 0;

    // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
    icmphdr.icmp_cksum = 0;

    char packet[IP_MAXPACKET];

    // Fill the packet, first the ICMP Header.
    memcpy(packet, &icmphdr, ICMP_HDRLEN);

    // Add the ICMP data.
    memcpy(packet + ICMP_HDRLEN, data, datalen);

    // Calc the ICMP header checksum.
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *) (packet), ICMP_HDRLEN + datalen);
    memcpy(packet, &icmphdr, ICMP_HDRLEN);

    struct sockaddr_in dest_in;
    memset(&dest_in, 0, sizeof(struct sockaddr_in));
    dest_in.sin_family = AF_INET;
    //
    dest_in.sin_addr.s_addr = inet_addr("8.8.8.8");

    // define time method for measuring.
    struct timeval start, end;
    double time = 0;

    // new socket.
    int sock = -1;
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        fprintf(stderr, "socket() failed with error: %d", errno);
        fprintf(stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }

    // start timer.
    gettimeofday(&start, 0);

    // Send the packet using sendto() for sending datagrams.
    if (sendto(sock, packet, ICMP_HDRLEN + datalen, 0, (struct sockaddr *) &dest_in, sizeof(dest_in)) == -1) {
        fprintf(stderr, "sendto() failed with error: %d", errno);
        return -1;
    }

    // receive the packet we send.
    if (recvfrom(sock, &packet, ICMP_HDRLEN + datalen, 0, NULL, (socklen_t *) sizeof(dest_in)) != 1) {
        printf("Packet received successfully.\n");
    } else {
        fprintf(stderr, "Error, the packet : %s\n, has not arrived", strerror(errno));
    }

    // stop timer.
    gettimeofday(&end, 0);
    double mil_sec = (end.tv_usec - start.tv_usec) / 1000 + (double) (end.tv_sec - start.tv_sec);
    double micro_sec = (end.tv_usec - start.tv_usec) + (double) (end.tv_sec - start.tv_sec);

    printf("Ping Time --- \t");
    printf("Milliseconds: -> %1.4f \t", mil_sec);
    printf("Microseconds: -> %1.4f \n", micro_sec);
    close(sock);
    return 0;

}

unsigned short calculate_checksum(unsigned short *paddress, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *((unsigned char *) &answer) = *((unsigned char *) w);
        sum += answer;
    }

    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}