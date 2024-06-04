#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    bpf_u_inet;

    printf("Escuchando por SYN-ACK...................\n");

    
    handle = pcap_open_live("docker0", BUFSIZ, 1, 1000, errbuf);

    pcap_compile(handle, &f, filter_exp, 0, net);
    if(pcap_setfilter(handle, &fp) =! 0)
    {
        pcap_error(handle, "Error");
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, -1, got_packet, null);
    pcap_close(handle);
    return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct sthheader *)packet;

    if(ntohs(eth->ether_type) == 0x0800){
        struct ipheader * ip = (struct ipheader *)(packet +sizeof(struct ethheader));

        printf("        From: %s\n",inet_ntoa(ip->iph_sourceip)); 
        printf("          to: %s\n",inet_ntoa(ip->iph_destip)); 

        switch(ip->iph_protocol){
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

