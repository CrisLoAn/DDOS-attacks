#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

#define SNAP_LEN 1518

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_header;
    struct tcphdr *tcp_header;
    int ip_header_length;

    // Obtener la cabecera IP
    ip_header = (struct ip*)(packet + sizeof(struct ether_header));
    ip_header_length = ip_header->ip_hl * 4;

    // Si no es un paquete TCP, lo ignoramos
    if (ip_header->ip_p != IPPROTO_TCP) return;

    // Obtener la cabecera TCP
    tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip_header_length);

    // Si es un paquete SYN-ACK, lo mostramos
    if (tcp_header->th_flags == TH_SYN) {
        // Mostrar información del paquete en una sola línea
        printf("SYN-ACK: Origen: %s, Destino: %s, Hora: %s", inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst), ctime((const time_t*)&pkthdr->ts.tv_sec));
    }
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[] = "tcp[tcpflags] & (tcp-syn | tcp-ack) == (tcp-syn | tcp-ack)";
    char *dev;

    printf("Inicio de la captura...........\n\n");

    // Verificar si se proporcionó un argumento para el nombre de la interfaz
    if (argc != 2) {
        fprintf(stderr, "Interfaz: %s <nombre_de_interfaz>\n", argv[0]);
        return 1;
    }

    // Obtener el nombre de la interfaz de red desde los argumentos
    dev = argv[1];

    // Abrir la interfaz de red para captura
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "No se pudo abrir la interfaz %s: %s\n", dev, errbuf);
        return 1;
    }

    // Compilar el filtro de expresión
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error al compilar el filtro de expresión: %s\n", pcap_geterr(handle));
        return 1;
    }

    // Aplicar el filtro de expresión
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error al aplicar el filtro de expresión: %s\n", pcap_geterr(handle));
        return 1;
    }

    // Comenzar la captura de paquetes
    pcap_loop(handle, 0, packet_handler, NULL);

    // Cerrar el manejador de captura
    pcap_close(handle);

    return 0;
}
