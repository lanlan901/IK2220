from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
import pox.lib.packet as pkt
from forwarding.l2_learning import LearningSwitch
import struct 
import ipaddress
log = core.getLogger()


# This is the basic Firewall class which implements all features of your firewall!
# For upcoming packets, you should decide if the packet is allowed to pass according to the firewall rules (which you have provided in networkFirewalls file during initialization.)
# After processing packets you should install the correct OF rule on the device to threat similar packets the same way on dataplane (without forwarding packets to the controller) for a specific period of time.

# rules format:
# [input_HW_port, protocol, src_subnet, src_port, dst_subnet, dst_port, allow/block]
# Checkout networkFirewalls.py file for detailed structure.

class Firewall (LearningSwitch):

    rules = []

    def __init__(self, connection, name):

        # Initialization of your Firewall. You may want to keep track of the connection, device name and etc.

        super(Firewall, self).__init__(connection, False)

        ### COMPLETE THIS PART ###
        self.connection = connection
        self.name = name
        # This binds the PacketIn event listener
        connection.addListeners(self)

    def do_firewall(self, packet, received_port):
        msg = of.ofp_flow_mod()                        # create a flow_mod to send packets
        msg.match = of.ofp_match.from_packet(packet, received_port)   # setting the match

        dstAddr = packet.dst
        out_port = -1

        if dstAddr in self.macToPort:
            out_port = self.macToPort[dstAddr]
        else:
            out_port = of.OFPP_FLOOD

        print(f"On {self.name} Rule Installed on Output Port: {out_port}")
        msg.actions.append(of.ofp_action_output(port = out_port))
        msg.idle_timeout = 10
        msg.hard_timeout = 30

        self.connection.send(msg)
        return


    def check_subnet(self, subnet, ip):
        if subnet == 'any':
            return True
        else:
            ip = str(ip)
            if ipaddress.ip_address(ip) in ipaddress.ip_network(subnet):
                return True
            else:
                return False
    
    def check_protocol(self, rule, protocol):
        if rule == 'any':
            return True

        if rule != protocol: #类型不匹配
            return False 
            
        else: 
            return True
        
    def check_port(self, rule, port):
        if rule == 'any':
            return True  
            
        if rule != str(port):
            return False 
        else:
            return True

    # Check if the incoming packet should pass the firewall.
    # It returns a boolean as if the packet is allowed to pass the firewall or not.
    # You should call this function during the _handle_packetIn event to make the right decision for the incoming packet.
    def has_access(self, ip_packet, input_port):
        ### COMPLETE THIS PART ###
        packet_protocol = ""
        src_ip = ip_packet.srcip
        dst_ip = ip_packet.dstip
        packet_src_port = -1
        packet_dst_port = -1
        if ip_packet.find('tcp'):
            packet_protocol = 'TCP'
            packet_src_port = ip_packet.find('tcp').srcport
            packet_dst_port = ip_packet.find('tcp').dstport
        elif ip_packet.find('udp'):
            packet_protocol = 'UDP'
            udp_pkt = ip_packet.find('udp')
            packet_src_port = udp_pkt.srcport
            packet_dst_port = udp_pkt.dstport
        elif ip_packet.find('icmp'):
            packet_protocol = 'ICMP'
            icmp_packet = ip_packet.find('icmp')
            icmp_type = icmp_packet.type
            if icmp_type == 0:  # ping reply
                return True
            if icmp_type == 8: #ping request
                pass

        print(f"packet protocol = {packet_protocol}, src ip = {src_ip}, dst ip ={dst_ip}")
            
        for rule in self.rules:
            hw_port, protocol, src_subnet, src_port, dst_subnet, dst_port, action = rule
            print(f"Rule details: HW Port: {hw_port}, Protocol: {protocol}, Source IP: {src_subnet}, "
                  f"Source Port: {src_port}, Destination IP: {dst_subnet}, Destination Port: {dst_port}, Action: {action}")
            
            if hw_port != 'any' and hw_port != input_port:
                continue 
            if protocol != 'any' and protocol != packet_protocol:
                continue     

            # 检查IP
            src_subnet_res = self.check_subnet(src_subnet, src_ip)
            print(f"Checking source IP subnet: Rule subnet = {src_subnet}, Packet IP = {src_ip}, Result = {src_subnet_res}")

            dst_subnet_res = self.check_subnet(dst_subnet, dst_ip)
            print(f"Checking destination IP subnet: Rule subnet = {dst_subnet}, Packet IP = {dst_ip}, Result = {dst_subnet_res}")
            if not (src_subnet_res and dst_subnet_res):
                continue

            # 检查端口
            src_port_res = self.check_port(src_port, packet_src_port)
            print(f"Checking source port: Rule port = {src_port}, Packet port = {packet_src_port}, Result = {src_port_res}")

            dst_port_res = self.check_port(dst_port, packet_dst_port)
            print(f"Checking destination port: Rule port = {dst_port}, Packet port = {packet_dst_port}, Result = {dst_port_res}")

            if not (src_port_res and dst_port_res):
                continue
            print(f"checking allow or block = {action}")

            if action == 'allow':
                print("allow")
                return True
            elif action == 'block':
                print("block")
                return False
        print("NO RULES MATCH")
        return False  #默认不通过

    # On receiving a packet from dataplane, your firewall should process incoming event and apply the correct OF rule on the device.

    def _handle_PacketIn(self, event):

        packet = event.parsed
        input_port = event.port
        dpid = event.connection.dpid
        mac_addr = packet.src
        where = f"switch {dpid} - port {input_port}" 
        core.controller.updatefirstSeenAt(mac_addr, where)

        if not packet.parsed:
            print(self.name, ": Incomplete packet received! controller ignores that")
            return
        else:
            print(self.name, ": packet received! ")
        #packet_in = event.ofp

        ### COMPLETE THIS PART ###
        ip_packet = packet.find('ipv4')
        if ip_packet:
            access_allowed = self.has_access(ip_packet, event.port)
            if access_allowed:
                log.debug(f"{self.name}: Packet allowed.")
                self.do_firewall(packet, input_port)
            else:
                log.debug(f"{self.name}: Packet dropped.")
                return
        #else:
            # handle non-IP packets normally
            #self.do_firewall(packet, input_port)
        
        super(Firewall, self)._handle_PacketIn(event)

    # You are allowed to add more functions to this file as your need (e.g., a function for installing OF rules)

                