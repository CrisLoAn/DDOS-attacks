#Eliminamos al switch en caso de existir

sudo ovs-vsctl del-br switch-DDOS

echo '-------------------------------------------------init test'

#Agregamos el SWITH

sudo ovs-vsctl add-br switch-DDOS

#levanto el switch

sudo ifconfig switch-DDOS

#agrego la interfaz de salida a internet a mi OVS switch

sudo ovs-vsctl add-port switch-DDOS eno2

sudo ifconfig eno2 0

sudo dhclient switch-DDOS

echo '-------------------------------------------------switch up'



#Agregamos los puertos al sistema

sudo ip tuntap add mode tap vp-usuario
sudo ip tuntap add mode tap vp-slaver
sudo ip tuntap add mode tap vp-slave1
sudo ip tuntap add mode tap vp-slave2
sudo ip tuntap add mode tap vp-server


sudo ifconfig vp-usuario up
sudo ifconfig vp-slaver up
sudo ifconfig vp-slave1 up
sudo ifconfig vp-slave2 up
sudo ifconfig vp-server up


#Los agregamos al ovs
sudo ovs-vsctl add-port switch-DDOS vp-usuario
sudo ovs-vsctl add-port switch-DDOS vp-slaver
sudo ovs-vsctl add-port switch-DDOS vp-slave1
sudo ovs-vsctl add-port switch-DDOS vp-slave2
sudo ovs-vsctl add-port switch-DDOS vp-server

echo '------------------------------------------------- switch created'
