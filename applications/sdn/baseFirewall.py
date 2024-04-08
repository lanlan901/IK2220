from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr
import pox.lib.packet as pkt
from forwarding import l2_learning
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


    # Check if the incoming packet should pass the firewall.
    # It returns a boolean as if the packet is allowed to pass the firewall or not.
    # You should call this function during the _handle_packetIn event to make the right decision for the incoming packet.
    def has_access(self, ip_packet, input_port):


        ### COMPLETE THIS PART ###

        # 0. 检查数据包类型
        tcp_udp_packet = ip_packet.payload
        for rule in self.rules:
            rule_port, protocol, src_ip, src_port, dst_ip, dst_port, action = rule
        
            # 检查端口号
            if rule_port != 'any' and rule_port != input_port:
                continue  # 端口不匹配，检查下一规则
        
            # 检查协议
            if protocol != 'any':
                if protocol.upper() == 'TCP' and not isinstance(tcp_udp_packet, pkt.tcp):
                    continue 
                if protocol.upper() == 'UDP' and not isinstance(tcp_udp_packet, pkt.udp):
                    continue

            # 检查源IP地址
            if src_ip != 'any' and not self.ip_match(src_ip, ip_packet.srcip):
                continue  # 源IP不匹配

            # 检查目的IP地址
            if dst_ip != 'any' and not self.ip_match(dst_ip, ip_packet.dstip):
                continue  # 目的IP不匹配
        
            # 判断动作
            return action == 'allow'

        return False  #默认不通过

    def ip_match(self, rule_ip, packet_ip):
        ip, mask = rule_ip.split('/')
        mask = int(mask)
        # 将IP地址转换为整数进行比较
        rule_ip_int = struct.unpack("!I", IPAddr(ip).toRaw())[0]
        packet_ip_int = struct.unpack("!I", IPAddr(packet_ip).toRaw())[0]
        # 应用子网掩码
        mask_int = (1<<mask) - 1 << (32 - mask)
        return (rule_ip_int & mask_int) == (packet_ip_int & mask_int)

    # On receiving a packet from dataplane, your firewall should process incoming event and apply the correct OF rule on the device.

    def _handle_PacketIn(self, event):

        packet = event.parsed
        if not packet.parsed:
            print(self.name, ": Incomplete packet received! controller ignores that")
            return
        ofp_msg = event.ofp

        ### COMPLETE THIS PART ###
        if self.has_access(packet, input_port):
            log.debug(f"{self.name}: Packet allowed.")
            # 处理允许通过的数据包
            self.act_like_switch(packet, event.ofp)
        else:
            log.debug(f"{self.name}: Packet dropped based on firewall rules.")
            
        super(Firewall, self)._handle_PacketIn(event)

    # You are allowed to add more functions to this file as your need (e.g., a function for installing OF rules)
