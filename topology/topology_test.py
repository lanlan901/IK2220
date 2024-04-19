
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Switch
from mininet.cli import CLI
from mininet.node import RemoteController
from mininet.node import OVSSwitch
from topology import *
import testing


topos = {'mytopo': (lambda: MyTopo())}


def run_tests(net):
    # You can automate some tests here

    # TODO: How to get the hosts from the net??
    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    h4 = net.get('h4')
    sw1 = net.get('sw1')
    sw2  = net.get('sw2')
    sw3 = net.get('sw3')
    sw4  = net.get('sw4')
    fw1 = net.get('fw1')
    fw2 = net.get('fw2')
    ws1  = net.get('ws1')
    ws2  = net.get('ws2')
    ws3 = net.get('ws3')


    # Launch some tests
    testing.ping(h1, h2, True)
    testing.ping(h1, h3, False)
    testing.ping(h3, h1, True)
    testing.ping(h3, h2, True)
    testing.ping(h2, h3, False)
    #testing.curl(h1, h2, expected=False)


if __name__ == "__main__":

    # Create topology
    topo = MyTopo()

    ctrl = RemoteController("c0", ip="127.0.0.1", port=6633)

    # Create the network
    net = Mininet(topo=topo,
                  switch=OVSSwitch,
                  controller=ctrl,
                  autoSetMacs=True,
                  autoStaticArp=True,
                  build=True,
                  cleanup=True)

    # Start the network
    net.start()

    startup_services(net)
    run_tests(net)

    # Start the CLI
    CLI(net)

    # You may need some commands before stopping the network! If you don't, leave it empty
    ### COMPLETE THIS PART ###

    net.stop()
