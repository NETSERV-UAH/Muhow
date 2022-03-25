#!/usr/bin/python
import socket, struct, os, array, uuid, time, sys
from scapy.all import *
import select, random
import threading
import signal
import time
import datetime
import re
from tabulate import tabulate

ETH_TYPE_CUSTOM = 65467 #valor del eth custom para hellos
TIME_OUT = 3000
NODE_NO_SDN = 2 #id del dispositivo switch no sdn
TIME_HELLO = 5 #segundos
TIME_ACTIVE_HELLO = 8 #segundos
TIME_INIT_PROPAGATION = 30
TIME_DEDENNE = 8 #segundos
TIME_ACTIVE_LABEL = 11 #segundos
MAX_DEDENNE_LABELS = 10 #etiquetas dedenne max por nodo
FLAG_HELLO_INFO = True
FLAG_DEDENNE_INFO = True
MAC_DST = 'FF:FF:FF:FF:FF:FF'

###############################################################################################################################################################################################
def handler(signum, frame):  #Kill all threads
    sys.exit()

###############################################################################################################################################################################################
class pkt_sniffer:

    def __init__(self):
        self.timeout = TIME_OUT
        self.node_mac = ''
        self.interface_name = ''
        self.inputs = []
        self.outputs = []
        self.message_queues = dict()
        self.info_neighbours = []
        self.node_label = []
        self.node_ID = 0
        self.hello_packet = 0
        self.label_propagation_packet = 0
        self.cnt_dedenne = 0
        self.flag_init_propagation = False
        self.cnt_neighbours = list(range(1,26))    #ID para 25 posibles vecinos por nodo
        self.node_type = 0  #1=ROOT / 2=PADRE / 3=EDGE

###############################################################################################################################################################################################
    def insert_interfaces(self, interface_name, mac_interface):
        new_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        new_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        new_socket.bind((interface_name, ETH_P_ALL))
        new_socket.settimeout(0.0)

        self.interface_name=interface_name
        self.node_mac=mac_interface

        if (int(re.findall('\d', interface_name)[0])) == 1:
            self.node_ID = int(re.findall('\d', interface_name)[0])

        self.inputs.append(new_socket)

        if self.node_ID == 1:  #Se define root
            self.node_label = ['1']
            self.node_type = 1 #NODO ROOT

        if not interface_name in self.message_queues.keys():
                self.message_queues[interface_name] = []

###############################################################################################################################################################################################
    def mac_from_list_to_str(self, mac):
        for i in range(len(mac)):
            mac[i]=mac[i].replace('0x', '')
            if len(mac[i]) == 1:
                mac[i]='0'+mac[i]
        mac='%s:%s:%s:%s:%s:%s' % (mac[0],mac[1],mac[2],mac[3],mac[4],mac[5])
        return(mac)

###############################################################################################################################################################################################
    def print_sniffer_info(self):
        if self.inputs:
            texto=[('Socket status', 'Open')]
            texto.append(('MAC Addr',self.node_mac))
            texto.append(('Interface name', self.interface_name))

            if self.node_ID == 1:
                texto.append(('Node ID', '%d (root)' % self.node_ID))
                texto.append(('Label Dedenne', '%s (root)' % self.node_label))
            #else:
            #    texto.append(('Node ID', self.node_ID))
            #    texto.append(('Label Dedenne', self.node_label))

        print(tabulate(texto, headers=['SOCKET INFO',''], tablefmt='fancy_grid'))
        print('\n---------------------------------------------------------\n')


###############################################################################################################################################################################################
    def pkt_creation(self, option):
        eth_header = {}
        eth_header["mac_src"] = self.node_mac.split(":")
        eth_header["mac_dst"] = MAC_DST.split(":")
        eth_header["eth_type"] = [hex(ETH_TYPE_CUSTOM >> i & 0xff) for i in (8,0)]

        #ID_hex = [hex(self.node_ID & 0xff)]
        option_hex = [hex(option & 0xff)]

        # [MAC_SRC MAC_DST ETH_TYPE]
        cabecera = struct.pack("!6B6B2B",
                int(bytes(eth_header["mac_dst"][0],'utf-8'),16), int(bytes(eth_header["mac_dst"][1],'utf-8'),16), int(bytes(eth_header["mac_dst"][2],'utf-8'),16),
                int(bytes(eth_header["mac_dst"][3],'utf-8'),16), int(bytes(eth_header["mac_dst"][4],'utf-8'),16), int(bytes(eth_header["mac_dst"][5],'utf-8'),16),
                int(bytes(eth_header["mac_src"][0],'utf-8'),16), int(bytes(eth_header["mac_src"][1],'utf-8'),16), int(bytes(eth_header["mac_src"][2],'utf-8'),16),
                int(bytes(eth_header["mac_src"][3],'utf-8'),16), int(bytes(eth_header["mac_src"][4],'utf-8'),16), int(bytes(eth_header["mac_src"][5],'utf-8'),16),
                int(bytes(eth_header["eth_type"][0],'utf-8'),16), int(bytes(eth_header["eth_type"][1],'utf-8'),16))

        # + [OPTION]
        cabecera += struct.pack("!1B", int(bytes(option_hex[0],'utf-8'),16))

        if option == 1:   #CREACIÓN DE HELLO INICIAL (CONOCER A VECINOS Y FORMAR TABLA DE VECINOS)
            # + [MAC_SRC ID]
            pkt = cabecera
            pkt += struct.pack("!6B",
                    int(bytes(eth_header["mac_src"][0],'utf-8'),16), int(bytes(eth_header["mac_src"][1],'utf-8'),16), int(bytes(eth_header["mac_src"][2],'utf-8'),16),
                    int(bytes(eth_header["mac_src"][3],'utf-8'),16), int(bytes(eth_header["mac_src"][4],'utf-8'),16), int(bytes(eth_header["mac_src"][5],'utf-8'),16))

            # + [PADDING]
            pkt += struct.pack("!43x")

            self.hello_packet = pkt     #PKT de 64B con la estructura [MAC_DST MAC_SRC ETH_TYPE | OPTION | MAC_SRC ID | PADDING]
                                        #                             |     --eth_header--      |        |  --data--  |

        if option == 2:
            for label in self.node_label:  #[label, t.vida]
                pkt = cabecera
                id_label=label[0].split('.')
                n_id_label=len(id_label)

                header = {}
                header["n_ID_label"] = [hex(n_id_label & 0xff)]
                header["label"]=[]
                for i in range(n_id_label):
                    header["label"].append(hex(int(id_label[i]) & 0xff))

                # + [long_HLMAC HLMAC Main_tree]
                pkt += struct.pack("!1B", int(bytes(header["n_ID_label"][0],'utf-8'),16))
                n_label = header["n_ID_label"][0].replace('0x','')
                for i in range(int(n_label)):
                    pkt += struct.pack("!1B", int(bytes(header["label"][i],'utf-8'),16))

                if label != '1':
                    if label[2] == 'Yes':
                        arbol=1
                    else:
                        arbol=0
                else:
                    arbol=0
                header["Main_tree"] = [hex(arbol & 0xff)]
                pkt += struct.pack("!1B", int(bytes(header["Main_tree"][0],'utf-8'),16))  #[MAIN_TREE] -> Flag de pertenencia al árbol principal

                for neigh in self.info_neighbours:
                    mac_neigh = neigh[0].split(":")
                    id_neigh = [hex(int(neigh[1]) & 0xff)]
                    pkt += struct.pack("!6B1B",
                                int(bytes(mac_neigh[0],'utf-8'),16), int(bytes(mac_neigh[1],'utf-8'),16), int(bytes(mac_neigh[2],'utf-8'),16),
                                int(bytes(mac_neigh[3],'utf-8'),16), int(bytes(mac_neigh[4],'utf-8'),16), int(bytes(mac_neigh[5],'utf-8'),16),
                                int(bytes(id_neigh[0],'utf-8'),16))

                # + [PADDING]
                n_bytes=16+int(n_label)+1+7*len(self.info_neighbours)
                padd_by=64-n_bytes
                if padd_by > 0:
                    pkt += struct.pack("!%dx" % padd_by)

                #print(pkt)
                self.label_propagation_packet = pkt   #PKT de 64B con la estructura [MAC_DST MAC_SRC ETH_TYPE | OPTION | N_IDs LABEL | PADDING]
                                            #                                       |     --eth_header--      |        |  --data--   |
                if self.node_ID != 1:
                    self.send_pkt(self.label_propagation_packet)

###############################################################################################################################################################################################
    def send_pkt(self, pkt): #Enviar el pkt
        self.outputs = self.inputs
        for interface in self.inputs:
            nombre_ifaz = self.interface_name
            if not nombre_ifaz in self.message_queues.keys():
                    self.message_queues[nombre_ifaz] = []

            self.message_queues[nombre_ifaz].append(pkt)

###############################################################################################################################################################################################
    def hello_loop(self): #Enviar el pkt
        while(1):
            self.send_pkt(self.hello_packet)
            time.sleep(TIME_HELLO)

###############################################################################################################################################################################################
    def print_info_neighbours(self):
        if self.info_neighbours and FLAG_HELLO_INFO:
            print(tabulate(self.info_neighbours, headers=['MAC', 'ID vecino', 'Estado', 'TTL'], tablefmt='fancy_grid', stralign='center'))

###############################################################################################################################################################################################
    def print_labels(self):
        if self.node_label and FLAG_DEDENNE_INFO:
            print('[INFO] Reglas aplicadas: máximo %d etiquetas' % (MAX_DEDENNE_LABELS))
            print(tabulate(self.node_label, headers=['HLMAC', 'Prev. hop ID', 'Main Tree', 'TTL'], tablefmt='fancy_grid', stralign='center'))

###############################################################################################################################################################################################
    def expiration_time(self):
        while(1):
            if self.info_neighbours:
                for entry in self.info_neighbours:
                    i=self.info_neighbours.index(entry)
                    self.info_neighbours[i][3] -= 1
                    if self.info_neighbours[i][3] == 0:
                        print('[INFO] Entrada caducada del vecino con ID %d' % self.info_neighbours[i][1])
                        self.cnt_neighbours.append(int(self.info_neighbours[i][1]))
                        if len(self.cnt_neighbours) < 3:
                            self.cnt_neighbours+=list(range(26,51))
                        self.cnt_neighbours.sort()
                        self.info_neighbours.remove(entry)
                        self.print_info_neighbours()

            self.cnt_dedenne +=1
            if self.cnt_dedenne == TIME_INIT_PROPAGATION:
                self.flag_init_propagation = True

            if self.node_label and self.node_label != ['1']:
                for label in self.node_label:
                    i=self.node_label.index(label)
                    self.node_label[i][3] -= 1
                    if self.node_label[i][3] == 0:
                        print('[INFO] Etiqueta caducada: %s' % self.node_label[i][0])
                        self.node_label.pop(i)
                        self.print_labels()

            time.sleep(1)

###############################################################################################################################################################################################
    def process_hello_pkt(self, data):
        mac = [hex(int(data[x])) for x in range(0,6)]
        mac_src = self.mac_from_list_to_str(mac)  #Conversión mac

        flag_existe=False
        for entry in self.info_neighbours:         #Comprobación de que no haya entradas repetidas y actualizacion t.vida
            if entry[0] == mac_src:
                flag_existe=True
                i=self.info_neighbours.index(entry)
                self.info_neighbours[i][3] = TIME_ACTIVE_HELLO

        if not flag_existe:
            id_vecino = self.cnt_neighbours[0]
            self.cnt_neighbours.pop(0)
            self.info_neighbours.append([mac_src, id_vecino, ' ', TIME_ACTIVE_HELLO])
            print('[INFO] Nuevo vecino descubierto con ID %s' % id_vecino)
            self.print_info_neighbours()

###############################################################################################################################################################################################
    def get_previous_hop(self,pkt):
        data = struct.unpack("!6B", pkt[6:12])
        mac_src='%02d:%02d:%02d:%02d:%02d:%02d' % (data[0],data[1],data[2],data[3],data[4],data[5])
        #print(mac_src)
        for neigh in self.info_neighbours:
            if neigh[0] == mac_src:
                return(neigh[1])
        return(0)

###############################################################################################################################################################################################
    def process_propagation_pkt(self, data, pkt):
        if self.node_ID != 1:
            data_rec = {}
            data_rec["option"] = int(data[2])
            data_rec["long_HLMAC"] = int(data[3])
            long_HLMAC = data_rec["long_HLMAC"]

            data = struct.unpack("!%dB" % (long_HLMAC+1), pkt[16:(16+long_HLMAC)+1])
            label_new=''
            for i in range(long_HLMAC):
                label_new+='%s.' % data[i]

            flag_main_tree=data[long_HLMAC]
            #print('Flag main_tree %s' % flag_main_tree)

            long_HLMAC+=1

            #print(pkt)
            data = struct.unpack("!7B", pkt[(16+long_HLMAC):(16+long_HLMAC+7)])
            mac_rcv = data[0:6]
            mac_rcv='%02d:%02d:%02d:%02d:%02d:%02d' % (mac_rcv[0],mac_rcv[1],mac_rcv[2],mac_rcv[3],mac_rcv[4],mac_rcv[5])

            ind=1
            while mac_rcv != self.node_mac:
                try:
                    if mac_rcv == '00:00:00:00:00:00':
                        break
                    data = struct.unpack("!7B", pkt[(16+long_HLMAC+7*ind):(16+long_HLMAC+7*ind+7)])
                    mac_rcv = data[0:6]
                    mac_rcv='%02d:%02d:%02d:%02d:%02d:%02d' % (mac_rcv[0],mac_rcv[1],mac_rcv[2],mac_rcv[3],mac_rcv[4],mac_rcv[5])
                    ind+=1
                except Exception as exception:
                    continue

            if mac_rcv == self.node_mac:
                id_node=data[6]
                label_new_2='%s%s' % (label_new,id_node)

                flag_exite_dedenne = False
                for label in self.node_label:
                    long = len(label_new)
                    if (long > len(label[0][0:len(label_new)])):
                        long = len(label[0][0:len(label_new)])

                    if label[0] == label_new_2:  #Ya tengo la etiqueta guardada, actualizo tiempo
                        flag_exite_dedenne = True
                        i = self.node_label.index(label)
                        self.node_label[i][3] = TIME_ACTIVE_LABEL
                        self.node_label[i][1] = self.get_previous_hop(pkt)
                        break
                    elif label[0][0:long] == label_new[0:long] and (label_new[0:long] != '1.' and label[0][0:long] != '1.'):  #Comprobación prefijo
                        #print('[INFO] Etiqueta no guardada porque coincide en prefijo con otra: %s' % label_new_2)
                        flag_exite_dedenne = True

                        #Si coincide el prefijo quitando los dos primeros dígitos => NODO HERMANO
                        if label_new[0:len(label_new)-4] == label:  #NODO HERMANO
                            id_hermano = int(label_new[len(label_new)-3:len(label_new)-2])
                            for neigh in self.info_neighbours:
                                if neigh[1] == id_hermano:
                                    i=self.info_neighbours.index(neigh)
                                    self.info_neighbours[i][2] = 'HERMANO'
                                    #self.print_info_neighbours()
                                    break

                        #Si prefijo ya está almacenado => NODO PADRE
                        else:
                            id_hijo = int(label_new[len(label_new)-2])
                            for neigh in self.info_neighbours:
                                if neigh[1] == id_hijo:
                                    i=self.info_neighbours.index(neigh)
                                    self.info_neighbours[i][2] = 'HIJO'
                                    break
                            #self.print_info_neighbours()
                            return

                        #Else => NODO EDGE

                if not flag_exite_dedenne:  #No tengo la etiqueta, la guardo
                    if self.node_label == []:
                        principal='Yes'
                    else:
                        principal = '-'

                    if len(self.node_label) < MAX_DEDENNE_LABELS:
                        if self.get_previous_hop(pkt) == 0:  #Hasta que no conozca al vecino, no añado su etiqueta
                            return

                        self.node_label.append([label_new_2, self.get_previous_hop(pkt),principal,TIME_ACTIVE_LABEL])
                        print('[INFO] New Dedenne Label: %s' % label_new_2)
                        self.print_labels()

###############################################################################################################################################################################################
    def check_node_status(self):
        for neigh in self.info_neighbours:
            if neigh[2] == 'HIJO':
                self.node_type = 2 #NODO PADRE
                print('[INFO] Nodo de tipo: PADRE')
                return
        if self.node_type == 1:
            print('[INFO] Nodo de tipo: ROOT')
        else:
            self.node_type = 3 #NODO EDGE
            print('[INFO] Nodo de tipo: EDGE')

###############################################################################################################################################################################################
    def init_propagation(self):
        while(1):
            if self.node_ID == 1:  #NODO ROOT
                if self.flag_init_propagation:
                    #if not self.label_propagation_packet: #Option=1 (Dedenne)
                    self.pkt_creation(2) #Option=1 (Dedenne)
                    print('[INFO] Iniciado propagación etiquetas')
                    self.send_pkt(self.label_propagation_packet)
                    self.check_node_status()
                    time.sleep(TIME_DEDENNE)
            else:    #RESTO DE NODOS
                if self.node_label != []:
                    self.pkt_creation(2) #Option=1 (Dedenne)
                    self.check_node_status()
                    time.sleep(TIME_DEDENNE)

###############################################################################################################################################################################################
    def recv(self):
        while True:
            readable, writable, exceptional = select.select(self.inputs, self.outputs, self.inputs, self.timeout/1000)

            for interface_readable in readable:
                    pkt, sa_ll = interface_readable.recvfrom(MTU)
                    if len(pkt) <= 0:
                            break

                    data = struct.unpack("!2B1B", pkt[12:15])   #Comprobación OPTION
                    option = int(data[2])

                    eth_type = [hex(int(data[x])) for x in range(0,2)] #Comprobación ETH_TYPE
                    eth_type[1]=eth_type[1].replace('0x', '')
                    eth_type_conv=eth_type[0] + eth_type[1]
                    eth_type_conv=int(eth_type_conv,16)

                    if eth_type_conv == ETH_TYPE_CUSTOM:
                        if option == 1:   #HELLO INICIAL
                            data = struct.unpack("!6B", pkt[15:21])  #ESTRUCTURA PKT HELLO
                            self.process_hello_pkt(data)

                        if option == 2:   #DEDENNE
                            data = struct.unpack("!2B1B1B", pkt[12:16])
                            self.process_propagation_pkt(data, pkt)

            for interface_writable in writable:
                n_msg=len(self.message_queues[self.interface_name])
                for msg in range (0, n_msg):
                    interface_writable.send(self.message_queues[self.interface_name][msg])
                self.message_queues[self.interface_name]=self.message_queues[self.interface_name][n_msg:]

###############################################################################################################################################################################################


###############################################################################################################################################################################################
pkt_sniff = pkt_sniffer()

#OBTENER INTERFACES
lista_intf = os.listdir('/sys/class/net/')
for interface in lista_intf:
    if interface.find("lo") != -1:     #interfaz de loopback
        continue
    elif interface.find("wlan") != -1:  #interfaz wireless
        fd = open('/sys/class/net/'+str(interface)+"/address","r")
        mac_interface = str(fd.read().split("\n")[0])
        pkt_sniff.insert_interfaces(interface, mac_interface)

pkt_sniff.print_sniffer_info()  #Info del socket abierto

#Creacion del paquete HELLO
pkt_sniff.pkt_creation(1) #Option=1 (HELLO INICIAL PARA DESCUBRIR VECINOS)

#Hilo para mensajes hello = 10seg
t_hello=threading.Thread(target=pkt_sniff.hello_loop)  #Envio hello pkt cada 5s
t_hello.daemon = True
t_hello.start()

t_expiration=threading.Thread(target=pkt_sniff.expiration_time)   #Comprobación caducidad tabla vecinos cada 1s
t_expiration.daemon = True
t_expiration.start()

#if NUM_ID == 1:
t_dedenne=threading.Thread(target=pkt_sniff.init_propagation)   #Hilo ejecución Dedenne
t_dedenne.daemon = True
t_dedenne.start()

signal.signal(signal.SIGINT, handler)

#Bucle recepción mensajes
pkt_sniff.recv()
