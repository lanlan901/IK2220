from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
import pox.lib.packet as pkt
from forwarding import l2_learning
import ipaddress
import time
log = core.getLogger()


# This is the basic Firewall class which implements all features of your firewall!
# For upcoming packets, you should decide if the packet is allowed to pass according to the firewall rules (which you have provided in networkFirewalls file during initialization.)
# After processing packets you should install the correct OF rule on the device to threat similar packets the same way on dataplane (without forwarding packets to the controller) for a specific period of time.

# rules format:
# [input_HW_port, protocol, src_ip, src_port, dst_ip, dst_port, allow/block]
# Checkout networkFirewalls.py file for detailed structure.

class Firewall (l2_learning.LearningSwitch):

    rules = []

    def __init__(self, connection, name):

        # Initialization of your Firewall. You may want to keep track of the connection, device name and etc.

        super(Firewall, self).__init__(connection, False)
        self.name = name
        
        ### COMPLETE THIS PART ###
        # self.pbztable = {str('00:00:00:00:00:01'), str('00:00:00:00:00:02')}
        # self.prztable = {str('00:00:00:00:00:03'), str('00:00:00:00:00:04')}
        # self.webserver = {str('00:00:00:00:00:05'), str('00:00:00:00:00:06'), str('00:00:00:00:00:07')}
        # self.allowtable = dict()


    def check_subnet(self, subnet, ip):
        if subnet == 'any':
            return True
        else:
            # 将 IPAddr 对象用于 IP 地址，确保格式正确
            try:
                ip_addr = ipaddress.ip_address(str(ip))
                network = ipaddress.ip_network(str(subnet), strict=False)  # 转换成字符串进行网络定义
                return ip_addr in network
            except ValueError as e:
                print(f"Error processing subnet {subnet} and IP {ip}: {e}")
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
            print(f"icmp type: {icmp_type}")
            #if icmp_type == 0:  # ping reply
                
            #     return True
            # if icmp_type == 8: #ping request
            #     pass

        print(f"input port = {input_port}, packet protocol = {packet_protocol}, src ip = {src_ip}, dst ip ={dst_ip}")
            
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
        if not packet.parsed:
            print(self.name, ": Incomplete packet received! controller ignores that")
            return

        self.process_packet(event, packet)

    def process_packet(self, event, packet):
        dpid = event.connection.dpid

        #src &dst
        src_mac = packet.src
        dst_mac = packet.dst
        # src_mac = packet.src
        # dst_mac = packet.dst
        print(f"src address: {src_mac}, dst address: {dst_mac}")
        #update first seen at
        where = f"switch {dpid} - port {event.port}" 
        core.controller.updatefirstSeenAt(src_mac, where)

        access_allowed = False #default block
        ip_packet = packet.find('ipv4')
        
        if not ip_packet:
            log.debug(f"No IPv4 packet found.")
            return
        
        log.debug(f"IP Protocol: {ip_packet.protocol}")
        print(ip_packet)
        access_allowed = self.has_access(ip_packet, event.port)

        protocol_handlers = {
            1: self.handle_icmp,
            6: self.handle_tcp
        }
        
        handler = protocol_handlers.get(ip_packet.protocol)
        if handler and event.port == 2:
            handler(event, packet, src_mac, dst_mac)
            return
            

        if access_allowed:
            super(Firewall, self)._handle_PacketIn(event)
            log.debug(f"{self.name}: Packet allowed.")
        else:
            log.debug(f"{self.name}: Packet blocked.")
            return
    
    def handle_icmp(self, event, packet, src_mac, dst_mac):
        log.debug(f"On {self.name} for ICMP : src address: {src_mac}, dst address: {dst_mac} create return rule")
        msg1 = of.ofp_flow_mod()
        msg1.match = of.ofp_match.from_packet(packet, event.port)
        msg1.idle_timeout = 10
        msg1.hard_timeout = 30
        msg1.actions.append(of.ofp_action_output(port = 2 if event.port == 1 else 1))
        msg1.data = event.ofp # 6a

        ip_packet = packet.find('ipv4')
        msg2 = of.ofp_flow_mod()

        #msg2.match = msg1.match.clone()
        msg2.match.in_port = 1
        msg2.match.dl_type = 0x0800
        msg2.match.nw_proto = 1
        msg2.match.dl_src = dst_mac  # 反转MAC地址，匹配原始目的MAC作为源MAC
        msg2.match.dl_dst = src_mac
        msg2.match.nw_src = ip_packet.dstip
        msg2.match.nw_dst = ip_packet.srcip
        msg2.idle_timeout = 10
        msg2.hard_timeout = 30
        msg2.actions.append(of.ofp_action_output(port = event.port))
        #msg2.data = event.ofp # 6a

        self.connection.send(msg1)
        log.debug(f"match conditions for msg1: {msg1.match}")
        self.connection.send(msg2)
        log.debug(f"match conditions for msg2: {msg2.match}")
        pass

    def handle_tcp(self, event, packet, src_mac, dst_mac):
        log.debug(f"On {self.name} for TCP : src address: {src_mac}, dst address: {dst_mac} create return rule")

        msg3 = of.ofp_flow_mod()
        msg3.match = of.ofp_match.from_packet(packet, event.port)
        msg3.match.tp_dst = 80
        msg3.idle_timeout = 2
        msg3.hard_timeout = 30
        msg3.actions.append(of.ofp_action_output(port = 2 if event.port == 1 else 1))
        msg3.data = event.ofp

        msg4 = of.ofp_flow_mod()
        msg4.match = msg3.match.flip(in_port = 1)
        msg4.actions.append(of.ofp_action_output(port = event.port))
        msg4.idle_timeout = 2
        msg4.hard_timeout = 30
        #msg4.data = event.ofp # 6a

        self.connection.send(msg3)
        log.debug(f"match conditions: {msg3.match}")
        self.connection.send(msg4)
        log.debug(f"match conditions: {msg4.match}")

        pass



    