from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
import pox.lib.packet as pkt
from forwarding.l2_learning import LearningSwitch
import struct 
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

        ### COMPLETE THIS PART ###
        self.connection = connection
        self.name = name

    def check_subnet(self, subnet, ip):
        if subnet == 'any':
            return True
        else:
            # 分割子网为IP地址和掩码
            net_ip, mask = subnet.split('/')
            net_ip = IPAddr(net_ip)
            ip = IPAddr(ip)
            mask = int(mask)

            # 将掩码转换为32位二进制数
            mask_bin = (0xffffffff << (32 - mask)) & 0xffffffff

            # 检查子网是否匹配
            if int(net_ip) & mask_bin == int(ip) & mask_bin:
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

        #检查数据包类型
        payload = ip_packet.payload
        packet_protocol = ""
        packet_src_ip = ip_packet.srcip
        packet_dst_ip = ip_packet.dstip
        packet_src_port = -1
        packet_dst_port = -1

        if ip_packet.find('tcp'):
            packet_protocol = 'TCP'
            packet_src_port = ip_packet.find('tcp').srcport
            packet_dst_port = ip_packet.find('tcp').dstport
        
        if ip_packet.find('udp'):
            packet_protocol = 'UDP'
        
        #check ICMP
        icmp_packet = ip_packet.find('icmp')
        if icmp_packet:
            icmp_type = icmp_packet.type
            if icmp_type == 0:
                return True
            
        for rule in self.rules:
            rule_port, protocol, src_ip, src_port, dst_ip, dst_port, action = rule
            if rule_port != 'any' and rule_port != input_port:
                continue 
        
            #检查协议
            self.check_protocol(protocol, packet_protocol)
            
            #检查ip
            self.check_subnet(src_ip, packet_src_ip)
            self.check_subnet(dst_ip, packet_dst_ip)

            #检查端口
            self.check_port(src_port,packet_src_port)
            self.check_port(dst_port,packet_dst_port)
        
            #判断动作
            if action == 'allow':
                print("allow")
                return True
            elif action == 'block':
                print("block")
                return False

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
        
        ofp_msg = event.ofp

        ### COMPLETE THIS PART ###
        ip_packet = packet.find('ipv4')
        if ip_packet:
            if self.has_access(packet, input_port):
                log.debug(f"{self.name}: Packet allowed.")
                # 处理允许通过的数据包
                self.allow(packet, input_port)
            else:
                log.debug(f"{self.name}: Packet dropped based on firewall rules.")
        
        super(Firewall, self)._handle_PacketIn(event)

    # You are allowed to add more functions to this file as your need (e.g., a function for installing OF rules)
    def allow(self, packet, input_port):
        match_obj = of.ofp_match.from_packet(packet, input_port)
        msg = of.ofp_flow_mod()
        msg.match = match_obj
        out_port = -1

        dst_mac = packet.dst
        
        if dst_mac in self.macToPort:
            out_port = self.macToPort[dst_mac]
        
        else:
            out_port = of.OFPP_FLOOD 	
        print("Rule Installed on Output Port: {}", out_port)
        msg.actions.append(of.ofp_action_output(port = out_port))
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        self.connection.send(msg)
        return

                