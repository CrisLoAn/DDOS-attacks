#!/bin/sh

echo '------------------------------------------------->process start up'

sudo ovs-vsctl del-br switch-DOS

# Crear el switch Open vSwitch
sudo ovs-vsctl add-br switch-DDOS
sudo ovs-vsctl add-port switch-DDOS eno2
sudo ifconfig eno2 0
sudo dhclient switch-DDOS

echo '------------------------------------------------->switch up'

# Configurar la conexión a Internet
# Habilitar el reenvío de paquetes
sudo sysctl -w net.ipv4.ip_forward=1

# Configurar reglas de NAT para traducir las direcciones IP de los contenedores a la dirección IP pública del host
sudo iptables -t nat -A POSTROUTING -s 172.18.0.0/16 -o tu_interfaz_de_salida -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -s 172.19.0.0/16 -o tu_interfaz_de_salida -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -s 172.20.0.0/16 -o tu_interfaz_de_salida -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -s 172.21.0.0/16 -o tu_interfaz_de_salida -j MASQUERADE
sudo iptables -t nat -A POSTROUTING -s 172.22.0.0/16 -o tu_interfaz_de_salida -j MASQUERADE

# Configuración de la interfaz de red para container1 y conexión a OVS
sudo docker network connect --ip 172.18.0.2 switch-DDOS proyecto_subnet1 proyecto-usuario-1

# Configuración de la interfaz de red para container2 y conexión a OVS
sudo docker network connect --ip 172.19.0.2 switch-DDOS proyecto_subnet2 proyecto-slaver-1

# Configuración de la interfaz de red para container3 y conexión a OVS
sudo docker network connect --ip 172.20.0.2 switch-DDOS proyecto_subnet3 proyecto_slave1-1

# Configuración de la interfaz de red para container4 y conexión a OVS
sudo docker network connect --ip 172.21.0.2 switch-DDOS proyecto_subnet4 proyecto_slave2-1

# Configuración de la interfaz de red para container5 y conexión a OVS
sudo docker network connect --ip 172.22.0.2 switch-DDOS proyecto_subnet5 proyecto-my_server-1

echo '------------------------------------------------->Dockers connected'
