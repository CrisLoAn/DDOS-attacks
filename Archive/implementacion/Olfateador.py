#!/usr/bin/python3

import pcap
import dpkt
import socket
import threading
import time
import csv
import os

# Estructura para almacenar la información de cada flujo
class FlowStats:
    def __init__(self):
        self.pkt_count = 0
        self.byte_count = 0
        self.start_time = None
        self.end_time = None
        self.tx_bytes = 0
        self.rx_bytes = 0

    def update(self, pkt_len, src_ip, dst_ip):
        self.pkt_count += 1
        self.byte_count += pkt_len
        if self.start_time is None:
            self.start_time = time.time()
        self.end_time = time.time()
        if src_ip == target_ip:
            self.tx_bytes += pkt_len
        if dst_ip == target_ip:
            self.rx_bytes += pkt_len

    def get_duration(self):
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0

    def get_packet_rate(self):
        duration = self.get_duration()
        if duration > 0:
            return self.pkt_count / duration
        return 0

    def get_kbps(self, byte_count):
        duration = self.get_duration()
        if duration > 0:
            return (byte_count * 8) / (duration * 1000)
        return 0

    def get_tx_kbps(self):
        return self.get_kbps(self.tx_bytes)

    def get_rx_kbps(self):
        return self.get_kbps(self.rx_bytes)

    def get_tot_kbps(self):
        return self.get_kbps(self.byte_count)

target_ip = "172.17.0.3"
interface = "docker0"
output_file = "/usr/local/src/DDOs-folder/config/registros.csv"

flows = {}

# Crear el archivo CSV y escribir el encabezado
if not os.path.exists(output_file):
    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["src", "dst", "pktcount", "bytecount", "dur", "Protocol", "port_no", "tx_bytes", "rx_bytes", "tx_kbps", "rx_kbps", "tot_kbps"])

def packet_handler(timestamp, packet):
    eth = dpkt.ethernet.Ethernet(packet)
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        return

    ip = eth.data
    if ip.p != dpkt.ip.IP_PROTO_TCP:
        return

    tcp = ip.data
    if tcp.flags & dpkt.tcp.TH_SYN:
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)

        # Solo registrar si el destino es la target_ip
        if dst_ip != target_ip:
            return

        flow_key = (src_ip, dst_ip, tcp.sport, tcp.dport)
        if flow_key not in flows:
            flows[flow_key] = FlowStats()
        flows[flow_key].update(len(packet), src_ip, dst_ip)

        flow_stats = flows[flow_key]

        # Escribir los detalles en el archivo CSV
        with open(output_file, mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
                src_ip, dst_ip, flow_stats.pkt_count, flow_stats.byte_count,
                f"{flow_stats.get_duration():.9f}", "TCP", tcp.sport,
                flow_stats.tx_bytes, flow_stats.rx_bytes,
                f"{flow_stats.get_tx_kbps():.2f}", f"{flow_stats.get_rx_kbps():.2f}", f"{flow_stats.get_tot_kbps():2f}"
            ])

        print(f"SYN: Origen: {src_ip}, Destino: {dst_ip}, Hora: {timestamp:.9f}, "
              f"Paquetes: {flow_stats.pkt_count}, Bytes: {flow_stats.byte_count}, Duración: {flow_stats.get_duration():.9f}s, "
              f"Protocolo: TCP, Puerto origen: {tcp.sport}, "
              f"TX Bytes: {flow_stats.tx_bytes}, RX Bytes: {flow_stats.rx_bytes}, "
              f"TX kbps: {flow_stats.get_tx_kbps():.9f}, RX kbps: {flow_stats.get_rx_kbps():.9f}, Total kbps: {flow_stats.get_tot_kbps():.9f}")

def capture_packets(interface, stop_event):
    pc = pcap.pcap(name=interface, immediate=True)
    pc.setfilter('tcp[tcpflags] & tcp-syn == tcp-syn')

    print(f"Inicio de la captura en la interfaz {interface} (solo SYN)...........")

    for timestamp, packet in pc:
        if stop_event.is_set():
            break
        packet_handler(timestamp, packet)

def main():
    stop_event = threading.Event()
    capture_thread = threading.Thread(target=capture_packets, args=(interface, stop_event))
    capture_thread.daemon = True
    capture_thread.start()

    try:
        while capture_thread.is_alive():
            capture_thread.join(timeout=1)
    except KeyboardInterrupt:
        print("Interrupción del usuario. Finalizando...")
        stop_event.set()
        capture_thread.join()

if __name__ == "__main__":
    main()
