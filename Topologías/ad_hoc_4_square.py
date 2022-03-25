#!/usr/bin/python
import sys
from mininet.log import setLogLevel, info
from mn_wifi.link import wmediumd, adhoc
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi
from mn_wifi.wmediumdConnector import interference

def topology(args):
    "Create a network."
    net = Mininet_wifi(link=wmediumd, wmediumd_mode=interference)

    info("*** Creating nodes\n")
    kwargs = dict()
    #if '-a' in args:
    kwargs['range'] = 55
    kwargs['antennaGain'] = 6

    sta1 = net.addStation('sta1', position='100,150,0', **kwargs)
    sta2 = net.addStation('sta2', position='150,150,0', **kwargs)
    sta3 = net.addStation('sta3', position='100,100,0', **kwargs)
    sta4 = net.addStation('sta4', position='150,100,0', **kwargs)
    net.setPropagationModel(model="logDistance", exp=4)

    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()
    net.plotGraph(max_x=250, max_y=250)

    info("*** Creating links\n")
    kwargs = dict()
    if '-b' in args:
        kwargs['txpower'] = 17

    net.addLink(sta1, cls=adhoc, intf='sta1-wlan0',ssid='adhocNet', mode='g', channel=5,ht_cap='HT40+', **kwargs)
    net.addLink(sta2, cls=adhoc, intf='sta2-wlan0',ssid='adhocNet', mode='g', channel=5,ht_cap='HT40+', **kwargs)
    net.addLink(sta3, cls=adhoc, intf='sta3-wlan0',ssid='adhocNet', mode='g', channel=5,ht_cap='HT40+', **kwargs)
    net.addLink(sta4, cls=adhoc, intf='sta4-wlan0',ssid='adhocNet', mode='g', channel=5,ht_cap='HT40+', **kwargs)

    info("*** Starting network\n")
    net.build()

    info("*** Running CLI\n")
    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology(sys.argv)
