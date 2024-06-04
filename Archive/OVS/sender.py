#!/usr/bin/python3

from scapy.all import *

print("Triggering TCP Ping Pong")

# Define la dirección IP de origen y destino
ip = IP(src="10.9.0.5", dst="192.168.100.23")

# Define el encabezado TCP con los puertos de origen y destino
tcp = TCP(sport=9090, dport=8080)

# Define los datos que se enviarán en el paquete TCP
data = b"Hello World!\n"

# Construye el paquete con IP, TCP y datos
pkt = ip/tcp/data

# Envía el paquete sin imprimir mensajes verbosos
while(True):
    send(pkt, verbose=0)

