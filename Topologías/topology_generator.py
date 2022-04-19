#!/usr/bin/python
import sys
import os
from mininet.log import setLogLevel, info
from mn_wifi.link import wmediumd, adhoc
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi
from mn_wifi.wmediumdConnector import interference
import time

def topology(args):
    "Create a network."
    net = Mininet_wifi(link=wmediumd, wmediumd_mode=interference)

    info("*** Creating nodes\n")
    kwargs = dict()
    kwargs['range'] = 90
    kwargs['antennaGain'] = 6

    sta=[]
    file=open('./Topologias/80-nodos.txt','r')
    i=1
    for line in file:
        line=line[0:len(line)-1]
        sta1 = net.addStation('sta%d' %i, position=line, **kwargs)
        sta.append(sta1)
        i+=1
    file.close()

    net.setPropagationModel(model="logDistance", exp=4)

    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()
    net.plotGraph(min_x=-100, max_x=1000, min_y=-100, max_y=1000)

    info("*** Creating links\n")
    kwargs = dict()
    kwargs['txpower'] = 20

    for i in range(len(sta)):
        net.addLink(sta[i], cls=adhoc, intf='sta%d-wlan0' % (i+1),ssid='adhocNet', mode='g', channel=5,ht_cap='HT40+', **kwargs)


    info("*** Starting network\n")
    net.build()

    os.system('sudo rm ./Logs/*')
    for i in range(len(sta)):
        sta[i].cmd('python3 nodos.py &')
        #else:
        #    sta[i].cmd('python3 nodos.py |& tee -a ./Logs/log_sta%d.txt &' % (i+1))

        #process['sta%d'%(i+1)]=pid
        #time.sleep(1)

    #print(process)
    #os.system('sudo chmod 777 ./Logs/*')

    info("*** Running CLI\n")
    CLI(net)

    #for i in range(len(sta)):
    #   sta[i].stop()

    info("*** Stopping network\n")
    #sta[14].stop()
    net.stop()
    os.system('sudo chmod 777 ./Logs/*')

if __name__ == '__main__':
    setLogLevel('info')
    topology(sys.argv)
