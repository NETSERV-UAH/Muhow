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
import random
import os
import multiprocessing

ETH_TYPE_CUSTOM = 65467 #valor del eth custom para hellos
TIME_OUT = 1000
NODE_NO_SDN = 2 #id del dispositivo switch no sdn
TIME_HELLO = 3 #segundos
TIME_ACTIVE_HELLO = 9 #segundos
TIME_INIT_PROPAGATION = 10
TIME_DEDENNE = 5 #segundos
#TIME_ACTIVE_LABEL = 12 #segundos
MAX_DEDENNE_LABELS = 10 #etiquetas dedenne max por nodo
FLAG_HELLO_INFO = True
FLAG_LABELS_INFO = True
DIGITOS_PREFIJO = 2
FLAG_PREFIJO = True
MAC_DST = 'FF:FF:FF:FF:FF:FF'
ID_ROOT = 23
FLAG_FILE = True
PATH = './Logs/'
TIME_INIT_LOAD = 30

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
        self.info_neighbours = []   #HELLO FRAMES
        self.node_label = []        #HLMAC FRAMES
        self.node_ID = 0
        self.hello_packet = 0
        self.label_propagation_packet = 0
        self.cnt = 0
        self.flag_init_propagation = False
        self.cnt_neighbours = list(range(1,26))    #ID para 25 posibles vecinos por nodo   (HELLO FRAMES)
        self.trees_table = []   #HLMAC FRAMES
        self.log_file = ''
        self.computational_load = 0
        self.flag_init_load = False
        self.sons_info = []    #LOAD FRAMES
        self.iteration = 0
        self.time_stamp = 0
        self.main_labels = []
        self.long_ant = 0
        self.value_ant = None
        self.tree_index = 0 #DE MOMENTO SOLO CAMINO PRINCIPAL
        self.timer_ACK = None
        self.flag_ACK = False

###############################################################################################################################################################################################
    def get_node_ID(self):
        return self.node_ID

###############################################################################################################################################################################################
    def insert_interfaces(self, interface_name, mac_interface):
        new_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        new_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
        new_socket.bind((interface_name, ETH_P_ALL))
        new_socket.settimeout(0.0)

        self.interface_name=interface_name
        self.node_mac=mac_interface
        self.inputs.append(new_socket)
        self.node_ID = int(re.findall('[0-9]+', interface_name)[0])
        self.log_file = PATH + 'log_sta%d.txt' % self.node_ID

        if self.node_ID == ID_ROOT:  #Se define root
            self.node_label = [['1', '-', 'PARENT', 'Yes', '-']]
            os.system('rm -f ./Logs/*')
            #f=open(PATH+'computing_info.txt','w')
            #f.write("{:<10} {:<10} {:<10} {:<20} {:<20} {:<12}\n".format('Node name', 'Node type', 'Node load', 'Children ID', 'Children load', 'Node balance'))
            #f.write('------------------------------------------------------------------------------\n')
            #f.close()
        else:
            self.computational_load = random.randint(-10,10)

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

            if self.node_ID == ID_ROOT:
                texto.append(('Node ID', '%d (root)' % self.node_ID))
                texto.append(('Label Dedenne', '%s (root)' % self.node_label[0][0]))
        self.write_on_file(tabulate(texto, headers=['SOCKET INFO',''], tablefmt='fancy_grid'))
        self.write_on_file('\n---------------------------------------------------------\n')


###############################################################################################################################################################################################
    def pkt_creation(self, option, label=[], timestamp=0,valor=0, src=''):
        eth_header = {}
        eth_header["mac_src"] = self.node_mac.split(":")

        if option == 3:  #UNICAST PARA LOAD PACKAGES
            dst=self.node_label[self.tree_index][4]
            eth_header["mac_dst"] = dst.split(":")
        elif option == 4:
            eth_header["mac_dst"] = src.split(":")
        else:   #BROADCAST PARA RESTO DE PACKAGES
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
            pkt = cabecera

            if self.node_ID == ID_ROOT:
                self.time_stamp = round(time.time() * 1000000) #timestamp en us
                #print('Time stamp root: %d' %self.time_stamp )
                self.write_on_file('\n---------------------------------------------------------')
                self.write_on_file('---   Nueva iteración desde root: %d    ---' % self.iteration)
                now = datetime.datetime.now()
                #print ("Nueva iteración desde root : ")
                self.write_on_file(now.strftime("%Y-%m-%d %H:%M:%S.%f"))
                self.write_on_file('---------------------------------------------------------')

                self.trees_table=[]
                self.sons_info=[]
                self.iteration += 1
                self.long_ant = 0
                self.value_ant = None

            timestamp_hex = [hex(self.time_stamp >> i & 0xff) for i in (56,48,40,32,24,16,8,0)]
            #print('Hex time_stamp: ' + str(timestamp_hex))
            pkt += struct.pack("!8B",
                    int(bytes(timestamp_hex[0],'utf-8'),16), int(bytes(timestamp_hex[1],'utf-8'),16), int(bytes(timestamp_hex[2],'utf-8'),16),
                    int(bytes(timestamp_hex[3],'utf-8'),16), int(bytes(timestamp_hex[4],'utf-8'),16), int(bytes(timestamp_hex[5],'utf-8'),16),
                    int(bytes(timestamp_hex[6],'utf-8'),16), int(bytes(timestamp_hex[7],'utf-8'),16))

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
            for i in range(int(n_label,16)):
                pkt += struct.pack("!1B", int(bytes(header["label"][i],'utf-8'),16))

            if label != '1':
                if label[3] == 'Yes':
                    arbol=1
                else:
                    arbol=0
            else:
                arbol=0
            header["Main_tree"] = [hex(arbol & 0xff)]
            pkt += struct.pack("!1B", int(bytes(header["Main_tree"][0],'utf-8'),16))  #[MAIN_TREE] -> Flag de pertenencia al árbol principal

            self.check_neigh_expiration()   #ACTUALIZAR TIME STAMPS
            for neigh in self.info_neighbours:
                mac_neigh = neigh[0].split(":")
                id_neigh = [hex(int(neigh[1]) & 0xff)]
                pkt += struct.pack("!6B1B",
                            int(bytes(mac_neigh[0],'utf-8'),16), int(bytes(mac_neigh[1],'utf-8'),16), int(bytes(mac_neigh[2],'utf-8'),16),
                            int(bytes(mac_neigh[3],'utf-8'),16), int(bytes(mac_neigh[4],'utf-8'),16), int(bytes(mac_neigh[5],'utf-8'),16),
                            int(bytes(id_neigh[0],'utf-8'),16))

            # + [PADDING]
            self.check_neigh_expiration()   #ACTUALIZAR TIME STAMPS
            n_bytes=16+int(n_label,16)+8+1+7*len(self.info_neighbours)
            padd_by=64-n_bytes
            if padd_by > 0:
                pkt += struct.pack("!%dx" % padd_by)

            self.label_propagation_packet = pkt   #PKT de 64B con la estructura [MAC_DST MAC_SRC ETH_TYPE | OPTION | N_IDs LABEL | PADDING]
                                        #                                       |     --eth_header--      |        |  --data--   |
            if self.node_ID != ID_ROOT:
                self.send_pkt(self.label_propagation_packet)

        if option == 3:     #COMPUTATIONAL LOAD SHARING FROM LEAFS
            pkt = cabecera
            if (self.computational_load+valor) >= 0: #POSITIVO = 0
                sign=0
            else:   #NEGATIVO = 1
                sign=1

            sign_hex = [hex(int(sign) & 0xff)]
            pkt += struct.pack("!1B", int(bytes(sign_hex[0],'utf-8'),16))  #[MAIN_TREE] -> Flag de pertenencia al árbol principal
            value = [hex(int(abs(self.computational_load+valor)) & 0xff)]
            pkt += struct.pack("!1B", int(bytes(value[0],'utf-8'),16))  #[MAIN_TREE] -> Flag de pertenencia al árbol principal
            pkt += struct.pack("!47x")

            self.send_pkt(pkt)
            self.write_on_file('[INFO] Paquete de carga enviado con %d a MAC %s' % ((self.computational_load+valor),dst))

            #self.timer_ACK=threading.Thread(target=self.wait_ACK, args=(pkt,))  #Hilo de espera de 1s para recepción de ACK
            self.timer_ACK=multiprocessing.Process(target=self.wait_ACK, args=(pkt,))
            #self.timer_ACK.daemon = True
            self.timer_ACK.start()
            self.write_on_file('[INFO] Iniciado timer de ACK')

        if option == 4:
            pkt = cabecera
            pkt += struct.pack("!49x")
            self.send_pkt(pkt)
            self.write_on_file('[INFO] ACK enviado a MAC %s' % src)

###############################################################################################################################################################################################
    def wait_ACK(self, pkt):
        while(1):
            time.sleep(1)
            if not self.flag_ACK:
                self.write_on_file('[INFO] No se ha recibido ACK: REENVÍO PAQUETE DE CARGA')
                self.send_pkt(pkt)
                break

###############################################################################################################################################################################################
    def write_on_file(self,line):
        if FLAG_FILE:
            f=open(self.log_file,'a')
            f.write(line+'\n')
            f.close()
        else:
            print(line)

###############################################################################################################################################################################################
    def write_computing_info(self, node_type, power, value):
        f=open(PATH+'computing_info_it_%d.txt' % (self.iteration-1),'a')
        f.write("{:<10} {:<10} {:<10} {:<20} {:<20} {:<12}\n".format(self.interface_name.split('-')[0], node_type, self.computational_load, str(self.trees_table[self.tree_index][3]), str(power), self.computational_load+value))
        f.close()

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
            self.check_neigh_expiration()   #ACTUALIZAR TIME STAMPS
            self.write_on_file(tabulate(self.info_neighbours, headers=['MAC', 'ID vecino', 't.stamp'], tablefmt='fancy_grid', stralign='center'))

###############################################################################################################################################################################################
    def print_labels(self):
        if self.node_label and FLAG_LABELS_INFO:
            if not FLAG_PREFIJO:
                self.write_on_file('[INFO] Reglas aplicadas: máximo %d etiquetas\n' % (MAX_DEDENNE_LABELS))
            else:
                self.write_on_file('[INFO] Reglas aplicadas: máximo %d etiquetas con prefijo de %d dígitos\n' % (MAX_DEDENNE_LABELS,DIGITOS_PREFIJO))
            #self.write_on_file(tabulate(self.node_label, headers=['HLMAC', 'Prev. hop ID', 'Node Type', 'Main Tree', 'TTL', 'Parent MAC'], tablefmt='fancy_grid', stralign='center'))
            self.write_on_file(tabulate(self.node_label, headers=['HLMAC', 'Prev. hop ID', 'Node Type', 'Main Tree', 'Parent MAC'], tablefmt='fancy_grid', stralign='center'))

###############################################################################################################################################################################################
    def print_trees_table(self):
        if self.trees_table and FLAG_LABELS_INFO:
            self.write_on_file(tabulate(self.trees_table, headers=['HLMAC', 'Tree', 'Node type', 'Son ID'], tablefmt='fancy_grid', stralign='center'))

###############################################################################################################################################################################################
    def print_sons_table(self):
        if self.sons_info:
            self.write_on_file(tabulate(self.sons_info, headers=['Son ID', 'Rcv load', 'Value'], tablefmt='fancy_grid', stralign='center'))

###############################################################################################################################################################################################
    '''
    def expiration_time(self):
        while(1):
            if self.info_neighbours:
                for entry in self.info_neighbours:  #COMPROBACIÓN TTL VECINO
                    status=[]
                    entry[2] -= 1
                    if entry[2] == 0:   #HA CADUCADO VECINO
                        self.write_on_file('[INFO] Entrada caducada del vecino con ID %d' % entry[1])
                        if self.trees_table:
                            for j in range(len(self.trees_table)):   #BORRO VECINO TABLA DE ÁRBOLES
                                if entry[1] in self.trees_table[j][3]:
                                    if len(self.trees_table[j][3]) == 1:
                                        self.trees_table[j][3] = []
                                        self.trees_table[j][2] = 'LEAF'
                                    else:
                                        self.trees_table[j][3].remove(entry[1])
                            self.print_trees_table()

                        self.cnt_neighbours.append(int(entry[1]))
                        if len(self.cnt_neighbours) < 3:
                            self.cnt_neighbours+=list(range(26,51))
                        self.cnt_neighbours.sort()
                        self.info_neighbours.remove(entry)   #BORRO VECINO TABLA DE VECINOS
                        self.print_info_neighbours()


            self.cnt +=1
            if self.cnt == TIME_INIT_PROPAGATION: #COMPROBACIÓN INICIO PROPAGACIÓN DE ETIQUETAS
                self.flag_init_propagation = True

            #print('Epoca: %d' % self.iteration)
            #if self.iteration == 4 and not self.flag_init_load:  #COMPROBACIÓN INICIO BALANCEO DE CARGA
                #self.write_on_file('[INFO] Iniciado proceso balance de carga de computación')
                #self.write_on_file('[INFO] Valor de carga computacional %d' %self.computational_load)
                #self.flag_init_load = True

            if self.node_label and self.node_label[0][0] != '1':  #COMPROBACIÓN TTL ETIQUETA
                for label in self.node_label:
                    i=self.node_label.index(label)
                    label[4] -= 1
                    if label[4] == 0:  #HA CADUCADO ETIQUETA
                        self.write_on_file('[INFO] Etiqueta caducada: %s' % label[0])

                        if self.trees_table:   #BORRO ETIQUETA TABLA DE ÁRBOLES
                            for tree in self.trees_table:
                                if label[0] == tree[0]:
                                    j = self.trees_table.index(tree)
                                    self.trees_table.pop(j)
                        self.node_label.pop(i)  #BORRO ETIQUETA TABLA DE ETIQUETAS
                        self.print_labels()
                        self.print_trees_table()
                    else:  #POSIBLE ACTUALIZACIÓN ESTADO TABLA DE ETIQUETAS EN FUNCION TABLA DE ÁRBOLES
                        status=[]
                        for tree in self.trees_table:
                            if tree[0] == label[0]:
                                status.append(tree[2])
                        flag_padre = False
                        for tipo in status:
                            if tipo == 'PARENT':
                                flag_padre=True
                                label[2] = 'PARENT'
                                break
                        if not flag_padre:
                            label[2] = 'LEAF'

            if self.trees_table:   #COMPROBACIÓN ELIMINACIÓN ENTRADAS REPETIDAS EN TABLA DE ÁRBOLES SI SON LEAF (Posible duplicado árbol principal al ser LEAF)
                for label in self.node_label:
                    same_label=[]
                    for tree in self.trees_table:
                        if tree[0] == label[0]:
                            same_label.append(tree)
                    if len(same_label) == 2:
                        if (same_label[0][2] == 'LEAF' and same_label[1][2] == 'LEAF') or same_label[1][2] == 'LEAF':
                            self.trees_table.remove(same_label[1])

            time.sleep(1)
    '''
###############################################################################################################################################################################################
    def comput_load_sharing(self):
        #while 1:
            #if self.flag_init_load:

        self.write_on_file('[INFO] Iniciado proceso balance de carga de computación')
        self.write_on_file('[INFO] Valor de carga computacional LEAF %d' %self.computational_load)
        #CAMINO SELECCIONADO (Ahora mismo CAMINO PRINCIPAL)
        #self.tree_index = 0

        #if (self.node_label[self.tree_index][2] == 'LEAF' or self.trees_table[self.tree_index][2] == 'LEAF') and self.flag_init_load:
        #time.sleep(5)
        #self.write_on_file('[INFO] Paquete de carga enviado')
        self.pkt_creation(3)
        #now = datetime.datetime.now()
        #print ("Fin envio paquete de carga : ")
        #print (now.strftime("%Y-%m-%d %H:%M:%S"))
        #self.write_computing_info([(self.interface_name,'Node type','Node load','Children','Children load', 'Final balance')])
        #self.computational_load = 0 #Ya se ha mandado la carga
        self.write_computing_info('LEAF',[], 0)
        #self.flag_init_load = False

        #self.computational_load = random.randint(-10,10) #Nuevo valor de carga para siguiente iteración
        #self.write_on_file('[INFO] Nuevo carga computacional %d' %self.computational_load)

        return
        '''
        elif (self.node_label[self.tree_index][2] == 'PARENT' and self.trees_table[self.tree_index][2] == 'PARENT'):  #Comprobar si ya se ha recibido la info de todos los vecinos
            flags=[]
            power=[]
            value=0
            for entry in self.sons_info:
                if entry[1]:
                    flags.append(entry[1])
                power.append(entry[2])
                value+=entry[2]

            if len(self.sons_info) == len(flags):
                #self.write_computing_info('PARENT',self.tree_index,power, value)
                self.computational_load += value
                self.write_on_file('[INFO] Actualizado valor de carga %d' % self.computational_load)
                if self.node_ID != ID_ROOT:   #El ROOT no comparte, solo actualiza su valor
                    self.pkt_creation(3)
                    self.write_on_file('[INFO] Paquete de carga enviado con %d' %self.computational_load)
                    self.write_computing_info('PARENT',self.tree_index,power, value)
                    #self.write_computing_info([('Node name','Node type','Node load','Children','Children load', 'Final balance')])
                    #self.computational_load = 0 #Ya se ha mandado la carga

                    self.computational_load = random.randint(-10,10) #Nuevo valor de carga para siguiente iteración

                else:
                    self.write_computing_info('ROOT',self.tree_index,power, value)
                    self.write_on_file('[INFO] --- BALANCE DE CARGA HA CONVERGIDO ---')
                    self.write_on_file('[INFO] ---        Balance total: %d        ---' %self.computational_load)
                #self.flag_init_load = False
                return
            '''
###############################################################################################################################################################################################
    def process_hello_pkt(self, data):
        mac = [hex(int(data[x])) for x in range(0,6)]
        mac_src = self.mac_from_list_to_str(mac)  #Conversión mac

        self.check_neigh_expiration()   #ACTUALIZAR TIME STAMP VECINOS

        flag_existe=False
        self.check_neigh_expiration()   #ACTUALIZAR TIME STAMPS
        for entry in self.info_neighbours:         #Comprobación de que no haya entradas repetidas y actualizacion t.vida
            if entry[0] == mac_src:
                flag_existe=True
                t_stamp = round(time.time() * 1000000) #timestamp en us
                entry[2] = t_stamp + TIME_ACTIVE_HELLO*1000000 #Tiempo de entrada activa en us

        if not flag_existe:
            self.check_neigh_expiration()   #ACTUALIZAR TIME STAMPS
            id_vecino = self.cnt_neighbours[0]
            self.cnt_neighbours.pop(0)
            t_stamp = round(time.time() * 1000000) #timestamp en us
            t_active = t_stamp + TIME_ACTIVE_HELLO*1000000 #Tiempo de entrada activa en us
            self.info_neighbours.append([mac_src, id_vecino, t_active])
            self.write_on_file('[INFO] Nuevo vecino descubierto con ID %s' % id_vecino)
            self.print_info_neighbours()


###############################################################################################################################################################################################
    def check_neigh_expiration(self):
        if self.info_neighbours:
            for neigh in self.info_neighbours:
                t_stamp = round(time.time() * 1000000) #timestamp en us
                if t_stamp > neigh[2]:
                    self.write_on_file('[INFO] Entrada caducada del vecino con ID %d' % neigh[1])
                    self.cnt_neighbours.append(int(neigh[1]))
                    self.cnt_neighbours.sort()
                    self.info_neighbours.remove(neigh)   #BORRO VECINO DE TABLA DE VECINOS

            #self.print_info_neighbours()

            if len(self.cnt_neighbours) < 3:
                self.cnt_neighbours+=list(range(26,51))

###############################################################################################################################################################################################
    def get_previous_hop(self,pkt):
        data = struct.unpack("!6B", pkt[6:12])
        mac_src='%s:%s:%s:%s:%s:%s' % (format(data[0], '02x'),format(data[1], '02x'),format(data[2], '02x'),format(data[3], '02x'),format(data[4], '02x'),format(data[5], '02x'))
        self.check_neigh_expiration()   #ACTUALIZAR TIME STAMPS
        for neigh in self.info_neighbours:
            if neigh[0] == mac_src:
                return(neigh[1])
        return(0)

###############################################################################################################################################################################################
    def process_propagation_pkt(self, data, pkt):
        data_rec = {}
        data_rec["option"] = int(data[2])
        data_rec["long_HLMAC"] = int(data[11])
        long_HLMAC = data_rec["long_HLMAC"]

        timestamp_rcv = struct.unpack("!8B", pkt[15:23])
        #timestamp_rcv = [hex(pkt[x]) for x in range(15,23)] #Obtenicion time stamp
        #print('Hex time_stamp rcv: ' + str(timestamp_rcv))
        #for i in range(0,8):
        #    timestamp_rcv[i]=timestamp_rcv[i].replace('0x', '')
        time_stamp_rcv='0x%s%s%s%s%s%s%s%s' % (format(timestamp_rcv[0], '02x'),format(timestamp_rcv[1], '02x'),format(timestamp_rcv[2], '02x'),format(timestamp_rcv[3], '02x'),format(timestamp_rcv[4], '02x'),format(timestamp_rcv[5], '02x'),format(timestamp_rcv[6], '02x'),format(timestamp_rcv[7], '02x'))
        #time_stamp_rcv=timestamp_rcv[0] + timestamp_rcv[1] +timestamp_rcv[2]+timestamp_rcv[3]+timestamp_rcv[4]+timestamp_rcv[5]+timestamp_rcv[6]+timestamp_rcv[7]
        #print(time_stamp_rcv)
        time_stamp_rcv=int(time_stamp_rcv,16)

        #print('time_stamp almacenado %d ' %self.time_stamp)
        #print('time_stamp recibido %d ' % time_stamp_rcv)
        if time_stamp_rcv < self.time_stamp:      #OLD ITERATION
            return
        elif time_stamp_rcv > self.time_stamp: #NEW ITERATION
            #BORRO TODA LA INFO Y ACTUALIZO EL TIME STAMP
            self.time_stamp = time_stamp_rcv
            self.node_label = []
            self.trees_table = []
            self.sons_info = []
            self.main_labels = []
            self.flag_init_load = False
            self.long_ant = 0
            self.value_ant = None
            self.flag_ACK = False
            self.computational_load = random.randint(-10,10) #Nuevo valor de carga para la iteración
            self.write_on_file('\n---------------------------------------------------------')
            self.write_on_file('---    Nueva iteración: %d    ---' %self.iteration)
            self.write_on_file('---------------------------------------------------------')
            print('[INFO] Nueva carga para nodo: %d' % self.computational_load)

            f=open(PATH+'computing_info_it_%d.txt' % self.iteration,'w')
            f.write("{:<10} {:<10} {:<10} {:<20} {:<20} {:<12}\n".format('Node name', 'Node type', 'Node load', 'Children ID', 'Children load', 'Node balance'))
            f.write('-----------------------------------------------------------------------------------------\n')
            f.close()
            self.iteration += 1


        data = struct.unpack("!%dB" % (long_HLMAC+1), pkt[24:(24+long_HLMAC)+1])
        label_new=''
        for i in range(long_HLMAC):
            label_new+='%s.' % data[i]

        flag_main_tree=data[long_HLMAC]
        long_HLMAC+=1

        data = struct.unpack("!7B", pkt[(24+long_HLMAC):(24+long_HLMAC+7)])
        mac_rcv = data[0:6]
        mac_rcv='%s:%s:%s:%s:%s:%s' % (format(mac_rcv[0], '02x'),format(mac_rcv[1], '02x'),format(mac_rcv[2], '02x'),format(mac_rcv[3], '02x'),format(mac_rcv[4], '02x'),format(mac_rcv[5], '02x'))
        ind=1
        while mac_rcv != self.node_mac:
            try:
                if mac_rcv == '00:00:00:00:00:00':
                    break
                data = struct.unpack("!7B", pkt[(24+long_HLMAC+7*ind):(24+long_HLMAC+7*ind+7)])
                mac_rcv = data[0:6]
                mac_rcv='%s:%s:%s:%s:%s:%s' % (format(mac_rcv[0], '02x'),format(mac_rcv[1], '02x'),format(mac_rcv[2], '02x'),format(mac_rcv[3], '02x'),format(mac_rcv[4], '02x'),format(mac_rcv[5], '02x'))
                ind+=1
            except Exception as exception:
                continue

        if mac_rcv == self.node_mac:   #I AM IN THE NEIGHBOUR LIST
            id_node=data[6]
            label_new_2='%s%s' % (label_new,id_node)

            if flag_main_tree:   #ALMACENAR ETIQUETAS DEL CAMINO PRINCIPAL PARA LUEGO DEDICIR SI LEAF
                self.main_labels.append(label_new_2)
                #print('main_labels: %s' % self.main_labels)

            data = struct.unpack("!6B", pkt[6:12])
            #mac_src = data[0:6]
            mac_src='%s:%s:%s:%s:%s:%s' % (format(data[0], '02x'),format(data[1], '02x'),format(data[2], '02x'),format(data[3], '02x'),format(data[4], '02x'),format(data[5], '02x'))

            flag_exite_dedenne = False
            if self.node_ID != ID_ROOT:
                for label in self.node_label:
                    long = len(label_new)
                    if (long > len(label[0][0:len(label_new)])):
                        long = len(label[0][0:len(label_new)])

                    if label[0] == label_new_2:  #Ya tengo la etiqueta guardada, actualizo TTL
                        flag_exite_dedenne = True
                        #label[4] = TIME_ACTIVE_LABEL
                        label[1] = self.get_previous_hop(pkt)
                        #GENERO MENSAJE Y LO ENVÍO CON label_new_2
                        self.pkt_creation(2,label)
                        break

                    elif label[0][0:long] == label_new[0:long] and (label_new[0:long] != '1.' and label[0][0:long] != '1.'):  #Comprobación prefijo = PREFIX
                        flag_exite_dedenne = True

                        if label_new_2[0:len(label_new_2)-4] == label: #Si coincide prefijo, NODO HERMANO, no hago nada (NO INTERESA)
                            break

                        ### ÁRBOL PRINCIPAL ###
                        if flag_main_tree == 1 and label[3] == 'Yes':
                            flag_tree = False
                            if self.trees_table != []:
                                for tree in self.trees_table:
                                    if label[0] == tree[0] and tree[1] == 'MAIN':
                                        flag_tree=True
                                        break
                            if not flag_tree or self.trees_table == []:
                                self.trees_table.append([label[0], 'MAIN','UNDEFINED',[]])

                            ### COMPROBACIÓN TIPO DE NODO ###
                            #Si coincide el prefijo quitando los dos primeros dígitos => NODO HERMANO
                            if label_new_2[0:len(label_new_2)-4] == label:
                                break

                            #Si prefijo ya está almacenado => NODO PADRE
                            else:
                                for entry in self.trees_table:
                                    if entry[0] == label[0] and entry[1] == 'MAIN':
                                        if entry[2] != 'PARENT':
                                            entry[2] = 'PARENT'

                                        id_hijo=int(label_new[len(label_new)-2])
                                        if not (id_hijo in entry[3]):
                                            entry[3].append(id_hijo)
                                            self.write_on_file('[INFO] Nuevo ID de hijo añadido al árbol principal: %s' % label[0])
                                            #self.print_trees_table()

                                            self.sons_info.append([id_hijo, False, 0])
                                            self.print_sons_table()

                                        if label[2] != 'PARENT':
                                            label[2] = 'PARENT'
                                            #self.write_on_file('[INFO] Nuevo ID de hijo añadido al árbol principal: %s' % label[0])
                                            #self.print_labels()
                                        break

                        ### ÁRBOLES SECUNDARIOS ###
                        else:
                            flag_tree = False
                            if self.trees_table != []:
                                for tree in self.trees_table:
                                    if label[0] == tree[0] and tree[1] == '-':
                                        flag_tree=True
                                        break
                            if not flag_tree or self.trees_table == []:
                                self.trees_table.append([label[0], '-','UNDEFINED',[]])

                            ### COMPROBACIÓN TIPO DE NODO ###
                            #Si coincide el prefijo quitando los dos primeros dígitos => NODO HERMANO
                            if label_new_2[0:len(label_new_2)-4] == label:
                                break

                            #Si prefijo ya está almacenado => NODO PADRE
                            else:
                                for entry in self.trees_table:
                                    if entry[0] == label[0] and entry[1] == '-':
                                        if entry[2] != 'PARENT':
                                            entry[2] = 'PARENT'

                                        id_hijo=int(label_new[len(label_new)-2])
                                        if not (id_hijo in entry[3]):
                                            entry[3].append(id_hijo)
                                            #self.write_on_file('[INFO] Nuevo ID de hijo añadido a: %s' % label[0])
                                            #self.print_trees_table()
                                        if label[2] != 'PARENT':
                                            label[2] = 'PARENT'
                                            #self.write_on_file('[INFO] Nuevo ID de hijo añadido a: %s' % label[0])
                                            #self.print_labels()
                                        break

                    elif FLAG_PREFIJO:
                        if label[0][0:(2*DIGITOS_PREFIJO)-1] == label_new_2[0:(2*DIGITOS_PREFIJO)-1]:
                            flag_exite_dedenne = True
                            break
                    if flag_exite_dedenne:
                        break


                if not flag_exite_dedenne:  #No tengo la etiqueta, la guardo = NEW PREFIX
                    if self.node_label == []:
                        principal='Yes'
                    else:
                        principal = '-'

                    if len(self.node_label) < MAX_DEDENNE_LABELS:
                        if self.get_previous_hop(pkt) == 0:  #Hasta que no conozca al vecino, no añado su etiqueta
                            return

                        #self.node_label.append([label_new_2, self.get_previous_hop(pkt),'UNDEFINED', principal,TIME_ACTIVE_LABEL, mac_src])
                        self.node_label.append([label_new_2, self.get_previous_hop(pkt),'UNDEFINED', principal, mac_src])

                        #self.write_on_file('[INFO] New Dedenne Label: %s' % label_new_2)
                        #self.print_labels()

                        #Actualizar tabla de árboles
                        if principal == 'Yes':
                            self.trees_table.append([label_new_2, 'MAIN','UNDEFINED',[]])
                        else:
                            self.trees_table.append([label_new_2, '-','UNDEFINED',[]])
                        self.write_on_file('[INFO] Nueva HLMAC añadida: %s' % label_new_2)
                        #self.print_trees_table()
                        #GENERO MENSAJE Y LO ENVÍO CON label_new_2
                        for label in self.node_label:
                            if label[0] == label_new_2:
                                self.pkt_creation(2,label)
                            #now = datetime.datetime.now()
                            #print ("Envío mensaje de etiqueta : ")
                            #print (now.strftime("%Y-%m-%d %H:%M:%S"))

                if flag_exite_dedenne and self.trees_table == []:
                    self.trees_table.append([self.node_label[0][0], 'MAIN','UNDEFINED',[]])
                    self.write_on_file('[INFO] Nueva entrada añadida: %s' % label_new_2)
                    #self.print_trees_table()

                #print('ETIQUETAS RECIBIDAS DEL ARBOL PRINCIPAL %s ' % self.main_labels)
                #print('TIPO NODO ARBOL PRINCIPAL %s' % self.node_label[0][2])
                #print('FLAG INIT LOAD ' + str(self.flag_init_load))
                #self.print_labels()
                #self.print_trees_table()
                self.check_neigh_expiration()   #ACTUALIZAR TIME STAMPS
                if len(self.info_neighbours) == 1 and mac_src == self.info_neighbours[0][0] and not self.flag_init_load:    #ONLY ONE NEIGHBOUR?
                    self.trees_table[0][2] = 'LEAF'
                    self.node_label[0][2] = 'LEAF'
                    self.write_on_file('[INFO] Solo tengo un vecino y él me ha pasado la etiqueta: LEAF')
                    self.print_labels()
                    self.print_trees_table()
                    self.flag_init_load = True
                    self.comput_load_sharing()

                elif (len(self.main_labels) == len(self.info_neighbours)) and self.trees_table[0][2] == 'UNDEFINED' and not self.flag_init_load:  #MORE THAN 1 NEIGHBOUR: CHECK INFO
                    #print(self.main_labels)
                    self.write_on_file('[INFO] Tengo toda la información de mis vecinos y no soy padre: LEAF')
                    #print(self.main_labels)
                    self.trees_table[0][2] = 'LEAF'
                    self.node_label[0][2] = 'LEAF'
                    self.print_labels()
                    self.print_trees_table()
                    self.flag_init_load = True
                    self.comput_load_sharing()

                #else:    #LOAD TIMER ENABLE
                #    self.load_thread=threading.Thread(target=self.wait_labels)  #Envio hello pkt cada 5s
                    #t_hello.daemon = True
                #    t_hello.start()

            else:   #PARA NODO ROOT: Tabla de árboles con hijos
                if self.trees_table == []:
                    self.trees_table.append(['1','MAIN','LEAF',[]])

                if label_new_2[0:len(label_new_2)-4] == '1':
                    data = struct.unpack("!6B", pkt[6:12])
                    mac_rcv='%s:%s:%s:%s:%s:%s' % (format(data[0], '02x'),format(data[1], '02x'),format(data[2], '02x'),format(data[3], '02x'),format(data[4], '02x'),format(data[5], '02x'))
                    self.check_neigh_expiration()   #ACTUALIZAR TIME STAMPS
                    for neigh in self.info_neighbours:
                        if neigh[0] == mac_rcv:
                            if not neigh[1] in self.trees_table[0][3]:
                                self.trees_table[0][2] = 'PARENT'
                                self.trees_table[0][3].append(neigh[1])
                                self.print_trees_table()
                                self.sons_info.append([neigh[1], False, 0])
                                #self.print_sons_table()


###############################################################################################################################################################################################
    def process_load_pkt(self, data, pkt):
        orig = struct.unpack("!6B", pkt[6:12])
        mac_rcv='%s:%s:%s:%s:%s:%s' % (format(orig[0], '02x'),format(orig[1], '02x'),format(orig[2], '02x'),format(orig[3], '02x'),format(orig[4], '02x'),format(orig[5], '02x'))
        self.write_on_file('[INFO] Recibido paquete de carga con MAC_src %s' % mac_rcv)

        self.pkt_creation(4,[],0,0,mac_rcv)    #ACK

        self.check_neigh_expiration()   #ACTUALIZAR TIME STAMPS
        for neigh in self.info_neighbours:
            if neigh[0] == mac_rcv:
                if neigh[1] in self.trees_table[0][3]:
                    sign=int(data[0])   #(+)=0 / (-)=1
                    value=int(data[1])
                    if sign:
                        value=-value

                    for son in self.sons_info:
                        if son[0] == neigh[1]:
                            son[1] = True
                            son[2] = value
                            self.print_sons_table()
                            break

        #self.tree_index=0
        self.print_labels()
        self.print_trees_table()
        if (self.node_label[self.tree_index][2] == 'PARENT' and self.trees_table[self.tree_index][2] == 'PARENT'):  #Comprobar si ya se ha recibido la info de todos los vecinos
            #print('ENTRO')
            flags=[]
            power=[]
            value=0
            for entry in self.sons_info:
                if entry[1]:
                    flags.append(entry[1])
                    power.append(entry[2])
                    value+=entry[2]   #CALCULATE GENERAL LOAD

            #print(len(self.sons_info))
            #print(len(flags))
            if len(self.sons_info) == len(flags):
                #self.computational_load += value
                #print(self.long_ant)
                #print(self.value_ant)
                if self.long_ant < len(self.sons_info) or self.value_ant != value:    #Para solo enviar si hay cambio de información (En nº vecinos o valor de carga): No constantemente
                    self.long_ant = len(self.sons_info)
                    self.value_ant = value
                    #self.print_sons_table()
                    if self.node_ID != ID_ROOT:   #El ROOT no comparte, solo actualiza su valor
                        self.print_labels()
                        self.print_trees_table()
                        #if self.long_ant < len(self.sons_info):
                            #self.long_ant = len(self.sons_info)
                        self.write_on_file('[INFO] Valor de carga computacional PADRE %d' % (self.computational_load))
                        self.write_on_file('[INFO] Actualizado valor de carga %d' % (self.computational_load+value))
                        self.pkt_creation(3,[],0,value)   #SEND LOAD FRAME
                        #self.write_on_file('[INFO] Paquete de carga enviado')
                        self.write_computing_info('PARENT',power, value)
                        #self.computational_load = random.randint(-10,10) #Nuevo valor de carga para siguiente iteración
                        #self.write_on_file('[INFO] Nuevo valor de carga %d' % self.computational_load)
                        #now = datetime.datetime.now()
                        #print ("Fin envio paquete de carga : ")
                        #print (now.strftime("%Y-%m-%d %H:%M:%S"))
                    else:
                        self.write_computing_info('ROOT',power, value)
                        self.write_on_file('[INFO] --- BALANCE DE CARGA HA CONVERGIDO ---')
                        self.write_on_file('[INFO] ---        Balance total: %d        ---' % (self.computational_load+value))
                        now = datetime.datetime.now()
                        self.write_on_file("[INFO] Fin procesado root : ")
                        self.write_on_file(now.strftime("%Y-%m-%d %H:%M:%S.%f"))
                        self.computational_load=0
                        #print(self.sons_info)
                        #for son in self.sons_info:
                        #    son[2] = 0
                        #    son[1] = False
            return

###############################################################################################################################################################################################
    def init_propagation(self):
        time.sleep(TIME_INIT_PROPAGATION)
        if self.trees_table == []:
            self.trees_table.append(['1','MAIN','PARENT',[]])
        while(1):
            #if self.node_ID == ID_ROOT:  #NODO ROOT
                #if self.flag_init_propagation:
            self.pkt_creation(2,self.node_label[0]) #Option=1 (Dedenne)
            #print(self.label_propagation_packet)
            #self.write_on_file('[INFO] Iniciado propagación etiquetas')
            self.send_pkt(self.label_propagation_packet)
            time.sleep(TIME_DEDENNE)

###############################################################################################################################################################################################
    def recv(self):
        while True:
            readable, writable, exceptional = select.select(self.inputs, self.outputs, self.inputs, self.timeout/1000)

            for interface_readable in readable:
                    pkt, sa_ll = interface_readable.recvfrom(MTU)
                    if len(pkt) <= 0:
                            break
                    #print(pkt)
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

                        elif option == 2:   #DEDENNE
                            #now = datetime.datetime.now()
                            #print ("Paquete tipo 2 recibido a : ")
                            #print (now.strftime("%Y-%m-%d %H:%M:%S"))
                            #print('Hora pkt recibido ' + str())
                            data = struct.unpack("!2B1B8B1B", pkt[12:24])
                            self.process_propagation_pkt(data, pkt)
                        elif option == 3:
                            #self.write_on_file('[INFO] Recibido paquete de carga')
                            data = struct.unpack("!1B1B" , pkt[15:17])
                            self.process_load_pkt(data, pkt)
                        elif option == 4:
                            #print('Recibido ACK')
                            data = struct.unpack("!6B" , pkt[6:12])
                            mac_rcv='%s:%s:%s:%s:%s:%s' % (format(data[0], '02x'),format(data[1], '02x'),format(data[2], '02x'),format(data[3], '02x'),format(data[4], '02x'),format(data[5], '02x'))
                            if mac_rcv == self.node_label[self.tree_index][4]:   #Recibido ACK de mi PADRE
                                self.flag_ACK = True
                                self.write_on_file('[INFO] ACK recibido del nodo PADRE con MAC %s' % mac_rcv)
                                self.timer_ACK.terminate()
                                self.timer_ACK = None

            for interface_writable in writable:
                n_msg=len(self.message_queues[self.interface_name])
                '''for msg in range (0, n_msg):
                    print('Envio paquete %s' % self.message_queues[self.interface_name][msg])
                    interface_writable.send(self.message_queues[self.interface_name][msg])
                    self.message_queues[self.interface_name].pop(msg) #nos cargamos ese mensaje
                #self.message_queues[self.interface_name]=self.message_queues[self.interface_name][n_msg:]
                '''
                for idx, msg in enumerate(self.message_queues[self.interface_name]):
                    #print('Envio paquete %s' % msg)
                    interface_writable.send(msg)
                    self.message_queues[self.interface_name].pop(idx) #nos cargamos ese mensaje
                '''try:
                    if self.message_queues.has_key(interface_writable):
                        self.message_queues.pop(interface_writable,None)

                    if interface_writable in self.outputs:
                        self.outputs.remove(interface_writable)
                except Exception as exception:
                    continue '''

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
# HELLO TIMER ENABLE
t_hello=threading.Thread(target=pkt_sniff.hello_loop)  #Envio hello pkt cada 5s
t_hello.daemon = True
t_hello.start()

#t_expiration=threading.Thread(target=pkt_sniff.expiration_time)   #Comprobación caducidad tabla vecinos cada 1s
#t_expiration.daemon = True
#t_expiration.start()

# HLMAC TIMER ENABLE
if pkt_sniff.get_node_ID() == ID_ROOT:
    t_dedenne=threading.Thread(target=pkt_sniff.init_propagation)   #Hilo ejecución Dedenne
    t_dedenne.daemon = True
    t_dedenne.start()

#t_load=threading.Thread(target=pkt_sniff.comput_load_sharing)   #Proceso compartición carga iniciado por LEAFs
#t_load.daemon = True
#t_load.start()

signal.signal(signal.SIGINT, handler)

#Bucle recepción mensajes
pkt_sniff.recv()    #MAIN PROGRAM
