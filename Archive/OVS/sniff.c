#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h> // Para la estructura ethhdr y las constantes ETH_P_IP


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    bpf_u_int32 net;

    printf("Escuchando por SYN-ACK...................\n");

    handle = pcap_open_live("docker0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", "docker0", errbuf);
        return(EXIT_FAILURE);
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethhdr *eth = (struct ethhdr *)packet;

    if (ntohs(eth->h_proto) == ETH_P_IP){
        struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));

        printf("        From: %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr)); 
        printf("          to: %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr)); 

        switch(ip->protocol){
            case IPPROTO_TCP:
                printf("    Protocol: TCP\n");
                return;
            case IPPROTO_UDP:
                printf("    Protocol: UDP\n");
                return;
            case IPPROTO_ICMP:
                printf("    Protocol: ICMP\n");
                return;
            default:
                printf("    Protocol: others\n");
                return;
        }
    }
}
