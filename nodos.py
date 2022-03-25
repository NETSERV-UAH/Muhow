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
TIME_HELLO = 3 #segundos
TIME_ACTIVE_HELLO = 9 #segundos
TIME_INIT_PROPAGATION = 20
TIME_DEDENNE = 4 #segundos
TIME_ACTIVE_LABEL = 12 #segundos
MAX_DEDENNE_LABELS = 10 #etiquetas dedenne max por nodo
FLAG_HELLO_INFO = True
FLAG_LABELS_INFO = True
DIGITOS_PREFIJO = 2
FLAG_PREFIJO = True
MAC_DST = 'FF:FF:FF:FF:FF:FF'
ID_ROOT = 1
FLAG_FILE = False
PATH = './Logs/'
TIME_INIT_LOAD = 60

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
        self.cnt = 0
        self.flag_init_propagation = False
        self.cnt_neighbours = list(range(1,26))    #ID para 25 posibles vecinos por nodo
        self.trees_table = []
        self.log_file = ''
        self.computational_load = 0
        self.flag_init_load = False
        self.sons_info = []

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

        #CARGA COMPUTACIONAL
        if self.node_ID == 2 or self.node_ID == 5:
            self.computational_load = 1
        if self.node_ID == 4 or self.node_ID == 7:
            self.computational_load = -1

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
    def pkt_creation(self, option, label=[]):
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

            for neigh in self.info_neighbours:
                mac_neigh = neigh[0].split(":")
                id_neigh = [hex(int(neigh[1]) & 0xff)]
                pkt += struct.pack("!6B1B",
                            int(bytes(mac_neigh[0],'utf-8'),16), int(bytes(mac_neigh[1],'utf-8'),16), int(bytes(mac_neigh[2],'utf-8'),16),
                            int(bytes(mac_neigh[3],'utf-8'),16), int(bytes(mac_neigh[4],'utf-8'),16), int(bytes(mac_neigh[5],'utf-8'),16),
                            int(bytes(id_neigh[0],'utf-8'),16))

            # + [PADDING]
            n_bytes=16+int(n_label,16)+1+7*len(self.info_neighbours)
            padd_by=64-n_bytes
            if padd_by > 0:
                pkt += struct.pack("!%dx" % padd_by)

            self.label_propagation_packet = pkt   #PKT de 64B con la estructura [MAC_DST MAC_SRC ETH_TYPE | OPTION | N_IDs LABEL | PADDING]
                                        #                                       |     --eth_header--      |        |  --data--   |
            if self.node_ID != ID_ROOT:
                self.send_pkt(self.label_propagation_packet)

        if option == 3:     #COMPUTATIONAL LOAD SHARING FROM EDGES
            pkt = cabecera
            if self.computational_load >= 0: #POSITIVO = 0
                sign=0
            else:   #NEGATIVO = 1
                sign=1

            sign_hex = [hex(int(sign) & 0xff)]
            #print('Sign hex %s' % sign_hex)
            pkt += struct.pack("!1B", int(bytes(sign_hex[0],'utf-8'),16))  #[MAIN_TREE] -> Flag de pertenencia al árbol principal

            value = [hex(int(abs(self.computational_load)) & 0xff)]
            #print('Value %s' % value)
            pkt += struct.pack("!1B", int(bytes(value[0],'utf-8'),16))  #[MAIN_TREE] -> Flag de pertenencia al árbol principal

            pkt += struct.pack("!47x")
            #print(pkt)
            self.send_pkt(pkt)


###############################################################################################################################################################################################
    def write_on_file(self,line):
        if FLAG_FILE:
            f=open(self.log_file,'a')
            f.write(line+'\n')
            f.close()
        else:
            print(line)

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
            self.write_on_file(tabulate(self.info_neighbours, headers=['MAC', 'ID vecino', 'TTL'], tablefmt='fancy_grid', stralign='center'))

###############################################################################################################################################################################################
    def print_labels(self):
        if self.node_label and FLAG_LABELS_INFO:
            if not FLAG_PREFIJO:
                self.write_on_file('[INFO] Reglas aplicadas: máximo %d etiquetas\n' % (MAX_DEDENNE_LABELS))
            else:
                self.write_on_file('[INFO] Reglas aplicadas: máximo %d etiquetas con prefijo de %d dígitos\n' % (MAX_DEDENNE_LABELS,DIGITOS_PREFIJO))
            self.write_on_file(tabulate(self.node_label, headers=['HLMAC', 'Prev. hop ID', 'Node Type', 'Main Tree', 'TTL'], tablefmt='fancy_grid', stralign='center'))

###############################################################################################################################################################################################
    def print_trees_table(self):
        if self.trees_table and FLAG_LABELS_INFO:
            self.write_on_file(tabulate(self.trees_table, headers=['HLMAC', 'Tree', 'Node type', 'Son ID'], tablefmt='fancy_grid', stralign='center'))

###############################################################################################################################################################################################
    def print_sons_table(self):
        if self.sons_info:
            self.write_on_file(tabulate(self.sons_info, headers=['Son ID', 'Rcv load', 'Value'], tablefmt='fancy_grid', stralign='center'))

###############################################################################################################################################################################################
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
                                        self.trees_table[j][2] = 'EDGE'
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
            if self.cnt == TIME_INIT_LOAD:  #COMPROBACIÓN INICIO BALANCEO DE CARGA
                self.write_on_file('[INFO] Iniciado proceso balance de carga de computación')
                self.write_on_file('[INFO] Valor de carga computacional %d' %self.computational_load)
                self.flag_init_load = True

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
                            label[2] = 'EDGE'

            if self.trees_table:   #COMPROBACIÓN ELIMINACIÓN ENTRADAS REPETIDAS EN TABLA DE ÁRBOLES SI SON EDGE (Posible duplicado árbol principal al ser edge)
                for label in self.node_label:
                    same_label=[]
                    for tree in self.trees_table:
                        if tree[0] == label[0]:
                            same_label.append(tree)
                    if len(same_label) == 2:
                        if (same_label[0][2] == 'EDGE' and same_label[1][2] == 'EDGE') or same_label[1][2] == 'EDGE':
                            self.trees_table.remove(same_label[1])

            time.sleep(1)

###############################################################################################################################################################################################
    def comput_load_sharing(self):
        while 1:
            if self.flag_init_load:
                #CAMINO SELECCIONADO (Ahora mismo CAMINO PRINCIPAL)
                camino_principal = 0
                #if self.node_ID != ID_ROOT:
                if self.trees_table[camino_principal][3] != [] and self.sons_info == []:  #CREACION DE TABLA DE HIJOS PARA CONTROLAR EL PASO
                    for hijo in self.trees_table[0][3]:
                        self.sons_info.append([hijo, False, 0])
                    self.write_on_file('[INFO] Información de hijos del camino principal')
                    self.print_sons_table()

                elif (self.node_label[camino_principal][2] == 'EDGE' or self.trees_table[camino_principal][2] == 'EDGE'):  #PROPAGACIÓN CARGA SOLO PARA EDGES
                    time.sleep(5)
                    self.write_on_file('[INFO] Paquete de carga mandado')
                    self.pkt_creation(3)
                    #self.computational_load = 0 #Ya se ha mandado la carga
                    self.flag_init_load = False
                    #return
                elif (self.node_label[camino_principal][2] == 'PARENT' and self.trees_table[camino_principal][2] == 'PARENT'):  #Comprobar si ya se ha recibido la info de todos los vecinos
                    flags=[]
                    value=0
                    for entry in self.sons_info:
                        if entry[1]:
                            flags.append(entry[1])
                        value+=entry[2]

                    if len(self.sons_info) == len(flags):
                        self.computational_load += value
                        self.write_on_file('[INFO] Actualizado valor de carga %d' % self.computational_load)
                        if self.node_ID != ID_ROOT:   #El ROOT no comparte, solo actualiza su valor
                            self.pkt_creation(3)
                            self.write_on_file('[INFO] Paquete de carga enviado con %d' %self.computational_load)
                            #self.computational_load = 0 #Ya se ha mandado la carga
                        else:
                            self.write_on_file('[INFO] --- BALANCE DE CARGA HA CONVERGIDO ---')
                            self.write_on_file('[INFO] ---        Balance total: %d        ---' %self.computational_load)
                        self.flag_init_load = False


###############################################################################################################################################################################################
    def process_hello_pkt(self, data):
        mac = [hex(int(data[x])) for x in range(0,6)]
        mac_src = self.mac_from_list_to_str(mac)  #Conversión mac

        flag_existe=False
        for entry in self.info_neighbours:         #Comprobación de que no haya entradas repetidas y actualizacion t.vida
            if entry[0] == mac_src:
                flag_existe=True
                entry[2] = TIME_ACTIVE_HELLO

        if not flag_existe:
            id_vecino = self.cnt_neighbours[0]
            self.cnt_neighbours.pop(0)
            self.info_neighbours.append([mac_src, id_vecino, TIME_ACTIVE_HELLO])
            self.write_on_file('[INFO] Nuevo vecino descubierto con ID %s' % id_vecino)
            self.print_info_neighbours()

###############################################################################################################################################################################################
    def get_previous_hop(self,pkt):
        data = struct.unpack("!6B", pkt[6:12])
        mac_src='%s:%s:%s:%s:%s:%s' % (format(data[0], '02x'),format(data[1], '02x'),format(data[2], '02x'),format(data[3], '02x'),format(data[4], '02x'),format(data[5], '02x'))
        for neigh in self.info_neighbours:
            if neigh[0] == mac_src:
                return(neigh[1])
        return(0)

###############################################################################################################################################################################################
    def process_propagation_pkt(self, data, pkt):
        data_rec = {}
        data_rec["option"] = int(data[2])
        data_rec["long_HLMAC"] = int(data[3])
        long_HLMAC = data_rec["long_HLMAC"]

        data = struct.unpack("!%dB" % (long_HLMAC+1), pkt[16:(16+long_HLMAC)+1])
        label_new=''
        for i in range(long_HLMAC):
            label_new+='%s.' % data[i]

        flag_main_tree=data[long_HLMAC]
        long_HLMAC+=1

        data = struct.unpack("!7B", pkt[(16+long_HLMAC):(16+long_HLMAC+7)])
        mac_rcv = data[0:6]
        mac_rcv='%s:%s:%s:%s:%s:%s' % (format(mac_rcv[0], '02x'),format(mac_rcv[1], '02x'),format(mac_rcv[2], '02x'),format(mac_rcv[3], '02x'),format(mac_rcv[4], '02x'),format(mac_rcv[5], '02x'))
        ind=1
        while mac_rcv != self.node_mac:
            try:
                if mac_rcv == '00:00:00:00:00:00':
                    break
                data = struct.unpack("!7B", pkt[(16+long_HLMAC+7*ind):(16+long_HLMAC+7*ind+7)])
                mac_rcv = data[0:6]
                mac_rcv='%s:%s:%s:%s:%s:%s' % (format(mac_rcv[0], '02x'),format(mac_rcv[1], '02x'),format(mac_rcv[2], '02x'),format(mac_rcv[3], '02x'),format(mac_rcv[4], '02x'),format(mac_rcv[5], '02x'))
                ind+=1
            except Exception as exception:
                continue

        if mac_rcv == self.node_mac:
            id_node=data[6]
            label_new_2='%s%s' % (label_new,id_node)

            flag_exite_dedenne = False
            if self.node_ID != ID_ROOT:
                for label in self.node_label:
                    long = len(label_new)
                    if (long > len(label[0][0:len(label_new)])):
                        long = len(label[0][0:len(label_new)])

                    if label[0] == label_new_2:  #Ya tengo la etiqueta guardada, actualizo TTL
                        flag_exite_dedenne = True
                        label[4] = TIME_ACTIVE_LABEL
                        label[1] = self.get_previous_hop(pkt)
                        #GENERO MENSAJE Y LO ENVÍO CON label_new_2
                        self.pkt_creation(2,label)
                        break

                    elif label[0][0:long] == label_new[0:long] and (label_new[0:long] != '1.' and label[0][0:long] != '1.'):  #Comprobación prefijo
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
                                self.trees_table.append([label[0], 'MAIN','EDGE',[]])

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
                                            self.write_on_file('[INFO] Nuevo ID de hijo añadido a: %s' % label[0])
                                            self.print_trees_table()

                                        if label[2] != 'PARENT':
                                            label[2] = 'PARENT'
                                            self.write_on_file('[INFO] Nuevo ID de hijo añadido a: %s' % label[0])
                                            self.print_labels()
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
                                self.trees_table.append([label[0], '-','EDGE',[]])

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
                                            self.write_on_file('[INFO] Nuevo ID de hijo añadido a: %s' % label[0])
                                            self.print_trees_table()
                                        if label[2] != 'PARENT':
                                            label[2] = 'PARENT'
                                            self.write_on_file('[INFO] Nuevo ID de hijo añadido a: %s' % label[0])
                                            self.print_labels()
                                        break

                    elif FLAG_PREFIJO:
                        if label[0][0:(2*DIGITOS_PREFIJO)-1] == label_new_2[0:(2*DIGITOS_PREFIJO)-1]:
                            flag_exite_dedenne = True
                            break

                    if flag_exite_dedenne:
                        break

                if not flag_exite_dedenne:  #No tengo la etiqueta, la guardo
                    if self.node_label == []:
                        principal='Yes'
                    else:
                        principal = '-'

                    if len(self.node_label) < MAX_DEDENNE_LABELS:
                        if self.get_previous_hop(pkt) == 0:  #Hasta que no conozca al vecino, no añado su etiqueta
                            return

                        self.node_label.append([label_new_2, self.get_previous_hop(pkt),'EDGE', principal,TIME_ACTIVE_LABEL])
                        self.write_on_file('[INFO] New Dedenne Label: %s' % label_new_2)
                        self.print_labels()

                        #Actualizar tabla de árboles
                        if principal == 'Yes':
                            self.trees_table.append([label_new_2, 'MAIN','EDGE',[]])
                        else:
                            self.trees_table.append([label_new_2, '-','EDGE',[]])
                        self.write_on_file('[INFO] Nueva entrada añadida: %s' % label_new_2)
                        self.print_trees_table()
                        #GENERO MENSAJE Y LO ENVÍO CON label_new_2
                        for label in self.node_label:
                            if label[0] == label_new_2:
                                self.pkt_creation(2,label)


                if flag_exite_dedenne and self.trees_table == []:
                    self.trees_table.append([self.node_label[0][0], 'MAIN','EDGE',[]])
                    self.write_on_file('[INFO] Nueva entrada añadida: %s' % label_new_2)
                    self.print_trees_table()

            else:   #PARA NODO ROOT: Tabla de árboles con hijos
                if self.trees_table == []:
                    self.trees_table.append(['1','MAIN','EDGE',[]])

                if label_new_2[0:len(label_new_2)-4] == '1':
                    data = struct.unpack("!6B", pkt[6:12])
                    mac_rcv='%s:%s:%s:%s:%s:%s' % (format(data[0], '02x'),format(data[1], '02x'),format(data[2], '02x'),format(data[3], '02x'),format(data[4], '02x'),format(data[5], '02x'))
                    for neigh in self.info_neighbours:
                        if neigh[0] == mac_rcv:
                            if not neigh[1] in self.trees_table[0][3]:
                                self.trees_table[0][2] = 'PARENT'
                                self.trees_table[0][3].append(neigh[1])
                                self.print_trees_table()

###############################################################################################################################################################################################
    def process_load_pkt(self, data, pkt):
        orig = struct.unpack("!6B", pkt[6:12])
        mac_rcv='%s:%s:%s:%s:%s:%s' % (format(orig[0], '02x'),format(orig[1], '02x'),format(orig[2], '02x'),format(orig[3], '02x'),format(orig[4], '02x'),format(orig[5], '02x'))
        #print(mac_rcv)
        for neigh in self.info_neighbours:
            if neigh[0] == mac_rcv:
                if neigh[1] in self.trees_table[0][3]:
                    sign=int(data[0])   #+=0 / -=1
                    value=int(data[1])
                    if sign:
                        value=-value
                    #self.write_on_file('[INFO] Recibido paquete de hijo con ID %d con carga %d' %(neigh[1],value))
                    #break
                    for son in self.sons_info:
                        if son[0] == neigh[1]:
                            son[1] = True
                            son[2] = value
                            self.print_sons_table()
                            return

###############################################################################################################################################################################################
    def init_propagation(self):
        if self.trees_table == []:
            self.trees_table.append(['1','MAIN','PARENT',[]])
        while(1):
            if self.node_ID == ID_ROOT:  #NODO ROOT
                if self.flag_init_propagation:
                    self.pkt_creation(2,self.node_label[0]) #Option=1 (Dedenne)
                    self.write_on_file('[INFO] Iniciado propagación etiquetas')
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

                        if option == 2:   #DEDENNE
                            data = struct.unpack("!2B1B1B", pkt[12:16])
                            self.process_propagation_pkt(data, pkt)
                        if option == 3:
                            #print('Recibido paquete de carga')
                            data = struct.unpack("!1B1B" , pkt[15:17])
                            self.process_load_pkt(data, pkt)

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

if pkt_sniff.get_node_ID() == ID_ROOT:
    t_dedenne=threading.Thread(target=pkt_sniff.init_propagation)   #Hilo ejecución Dedenne
    t_dedenne.daemon = True
    t_dedenne.start()

t_load=threading.Thread(target=pkt_sniff.comput_load_sharing)   #Comprobación caducidad tabla vecinos cada 1s
t_load.daemon = True
t_load.start()

signal.signal(signal.SIGINT, handler)

#Bucle recepción mensajes
pkt_sniff.recv()
