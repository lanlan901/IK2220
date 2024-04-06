
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Switch
from mininet.cli import CLI
from mininet.node import RemoteController
from mininet.node import OVSSwitch


class MyTopo(Topo):
    def __init__(self):

        # Initialize topology
        Topo.__init__(self)

        # Here you initialize hosts, web servers and switches
        # (There are sample host, switch and link initialization,  you can rewrite it in a way you prefer)
        ### COMPLETE THIS PART ###

        # Initialize hosts
        h1 = self.addHost('h1', ip = '100.0.0.10/24')
        h2 = self.addHost('h2', ip = '100.0.0.11/24')
        h3 = self.addHost('h3', ip = '10.0.0.50/24')
        h4 = self .addHost('h4', ip = '10.0.0.51/24')

        # Initial switches
        sw1 = self.addSwitch('sw1')
        sw2 = self.addSwitch('sw2')
        sw3 = self.addSwitch('sw3')
        sw4 = self.addSwitch('sw4')

        # Web servers
        sw1 = self.addHost('ws1', ip = '100.0.0.40/24')
        sw2 = self.addHost('ws2', ip = '100.0.0.41/24')
        sw3 = self.addHost('ws3', ip = '100.0.0.42/24')

        # Firewalls
        fw1 = self.addSwitch('fw1', dpid = '11')
        fw2 = self.addSwitch('fw2', dpid = '12')

        # Defining links
        # Public zone
        self.addLink(sw1, h1, port1 = 1, port2 = 0)
        self.addLink(sw1, h2, port1 = 2, port2 = 0)

        # Private zone
        self.addLink(sw3, h3, port1 = 1, port2 = 0)
        self.addLink(sw3, h4, port1 = 2, port2 = 0)

        # Demilitarized Zone
        self.addLink(sw4, sw1, port1 = 1, port2 = 0)
        self.addLink(sw4, sw2, port1 = 2, port2 = 0)
        self.addLink(sw4, sw3, port1 = 3, port2 = 0)

        # Firewall
        self.addLink(sw1, fw1, port1 = 3, port2 = 1)
        self.addLink(sw2, fw1, port1 = 1, port2 = 2)
        self.addLink(sw2, fw2, port1 = 2, port2 = 1)

def startup_services(net):
    # Start http services and executing commands you require on each host...
    ### COMPLETE THIS PART ###
    pass



topos = {'mytopo': (lambda: MyTopo())}

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

    startup_services(net)
    # Start the network
    net.start()

    # Start the CLI
    CLI(net)

    # You may need some commands before stopping the network! If you don't, leave it empty
    ### COMPLETE THIS PART ###

    net.stop()
