#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h> // Agregar la inclusión de <string.h> para strcmp

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

    // Obtener la dirección IP de origen y destino
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // Si es un paquete SYN entrante o saliente relacionado con el servidor web, lo mostramos
    if ((tcp_header->th_flags & TH_SYN) && !(tcp_header->th_flags & TH_ACK)) {
        if (strcmp(src_ip, user_data) == 0 || strcmp(dst_ip, user_data) == 0) {
            printf("SYN: Origen: %s, Destino: %s, Hora: %s", src_ip, dst_ip, ctime((const time_t*)&pkthdr->ts.tv_sec));
        }
    }
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[100];  // Aumentar el tamaño para la expresión del filtro
    char *dev;

    // Verificar si se proporcionó un argumento para la dirección IP del servidor web
    if (argc != 3) {
        fprintf(stderr, "Uso: %s <nombre_de_interfaz> <direccion_ip_servidor_web>\n", argv[0]);
        return 1;
    }

    // Obtener el nombre de la interfaz de red desde los argumentos
    dev = argv[1];
    char *web_server_ip = argv[2];

    // Construir la expresión del filtro para capturar paquetes SYN entrantes y salientes relacionados con el servidor web
    snprintf(filter_exp, sizeof(filter_exp), "tcp[tcpflags] & tcp-syn != 0 and host %s", web_server_ip);

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
    pcap_loop(handle, 0, packet_handler, (u_char *)web_server_ip);

    // Cerrar el manejador de captura
    pcap_close(handle);

    return 0;
}
