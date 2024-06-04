#!/usr/bin/python3

import pcap
import dpkt
import socket
import threading

def packet_handler(timestamp, packet):
    eth = dpkt.ethernet.Ethernet(packet)
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        return

    ip = eth.data
    if ip.p != dpkt.ip.IP_PROTO_TCP:
        return

    tcp = ip.data
    if tcp.flags & dpkt.tcp.TH_SYN:
        print("SYN: Origen: {}, Destino: {}, Hora: {}".format(socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), timestamp))

def capture_packets(bridge_name):
    # Abrir la interfaz del switch de OVS para captura
    pc = pcap.pcap(name=bridge_name, immediate=True)

    # Aplicar el filtro de expresión para capturar solo los paquetes TCP con la bandera SYN
    pc.setfilter('tcp[tcpflags] & tcp-syn == tcp-syn')

    print(f"Inicio de la captura en la interfaz {bridge_name} (solo SYN)...........")

    # Comenzar la captura de paquetes en un bucle infinito
    for timestamp, packet in pc:
        packet_handler(timestamp, packet)

def main():
    bridge_name = "docker0"  # Especifica el nombre de la interfaz a monitorear

    # Crear y ejecutar un hilo para la captura de paquetes
    capture_thread = threading.Thread(target=capture_packets, args=(bridge_name,))
    capture_thread.daemon = True
    capture_thread.start()

    # El programa principal sigue ejecutándose aquí
    # Puedes agregar otras tareas que desees realizar en paralelo con la captura de paquetes

    # Esperar a que el hilo de captura termine (esto nunca sucederá en este ejemplo)
    capture_thread.join()

if __name__ == "__main__":
    main()
