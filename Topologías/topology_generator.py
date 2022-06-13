#!/usr/bin/python
import sys
import os
from mininet.log import setLogLevel, info
from mn_wifi.link import wmediumd, adhoc, adhocmultinodes
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi
#from mn_wifi.wmediumdConnector import interference
import time
from mininet.link import Intf, TCIntf, Link

#FICHERO_TOPO = '/home/arppath/TFM/Topologias/Pruebas-protocolo/Leizpiz/60/Leizpiz_60_7.txt'
FICHERO_TOPO = sys.argv[1]
CRITERIO = sys.argv[2]
PATH_LOGS = '/home/arppath/TFM/Logs/'

def topology(args):
    #print(sys.argv[1])
    "Create a network."
    #net = Mininet_wifi(link=wmediumd, wmediumd_mode=interference)
    net = Mininet_wifi(link=TCIntf)

    info("*** Creating nodes\n")
    kwargs = dict()
    #kwargs['range'] = 60
    #kwargs['antennaGain'] = 3

    kwargs['antennaGain'] = 6

    sta=[]
    #file=open('./Topologias/Pruebas-protocolo/Berlin/40/Berlin_40_1.txt','r')
    file=open(FICHERO_TOPO,'r')
    i=1
    for line in file:
        line=line[0:len(line)-1]
        elem=line.split(',')

        sta1 = net.addStation('sta%d' %i, position='%s,%s,%s' % (elem[0], elem[1], elem[2]), **kwargs)
        sta.append(sta1)
        i+=1
    file.close()

    net.setPropagationModel(model="logDistance", exp=4.2)

    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()
    #net.plotGraph(min_x=-100, max_x=1000, min_y=-100, max_y=1000)

    info("*** Creating links\n")
    kwargs = dict()
    kwargs['txpower'] = 20
    #kwargs['loss'] = '0.00000000000000000000001%'
    #kwargs['txpower'] = 17


    for i in range(len(sta)):
        net.addLink(sta[i], cls=adhocmultinodes, intf='sta%d-wlan0' % (i+1), ssid='adhocNet', mode='g', channel=5, ht_cap='HT40+', **kwargs)


    info("*** Starting network\n")
    net.build()

    #os.system('sudo rm ' + PATH_LOGS + '*')
    for i in range(len(sta)):
        sta[i].cmd('python3 /home/arppath/TFM/nodos.py %s %d &' % (sys.argv[1], int(sys.argv[2])))
        #else:
        #    sta[i].cmd('python3 nodos.py |& tee -a ./Logs/log_sta%d.txt &' % (i+1))

        #process['sta%d'%(i+1)]=pid
        #time.sleep(1)

    #print(process)
    #os.system('sudo chmod 777 ./Logs/*')

    info("*** Running CLI\n")
    #os.system()
    #CLI(net)
    net.start()

    #for i in range(len(sta)):
    #   sta[i].stop()
    files = os.listdir(PATH_LOGS)
    #print( len(files))
    while ('info_it_1.txt' not in files):# and ('linea_sta1.txt' in files)):
        files = os.listdir(PATH_LOGS)
        #print (files)

    #result = os.system('ps aux | grep \'sudo python3 Topologias/\'')
    #print(result)
    #net.stop()
    #os.system('sudo chmod 777 /home/arppath/TFM/Logs/*')
    info("*** Stopping network\n")
    #sta[14].stop()
    net.stop()
    os.system('sudo chmod 777 /home/arppath/TFM/Logs/*')
    os.system('rm ./Logs/linea_sta*')
    #os.system('rm ./Logs/log_sta*')

if __name__ == '__main__':
    setLogLevel('info')
    topology(sys.argv)
