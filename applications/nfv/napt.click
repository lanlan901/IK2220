define($PORT1 napt-eth1, $PORT2 napt-eth2)
define($PRZ_IP 10.0.0.1)
define($DMZ_IP 100.0.0.1)

// counters
cnt_in1, cnt_in2, cnt_out1, cnt_out2 :: AverageCounter; 
arp_req1, arp_req2, arp_res1, arp_res2 :: Counter;
drop1, drop2 :: Counter;

// interfaces
from_prz :: FromDevice($PORT2, METHOD LINUX, SNIFFER false);
from_dmz :: FromDevice($PORT1, METHOD LINUX, SNIFFER false);
to_prz :: Queue -> cnt_out1 -> ToDevice($PORT2);
to_dmz :: Queue -> cnt_out2 -> ToDevice($PORT1);

// IP rewrite
ipRewrite :: IPRewriter(pattern $DMZ_IP 1024-65534 - - 0 1);

// ICMP rewrite
icmp_rw_prz_to_dmz :: ICMPPingRewriter(
    pattern $PRZ_IP - $DMZ_IP,
    TIMEOUT 300,
    DST_ANNO true
);

icmp_rw_dmz_to_prz :: ICMPPingRewriter(
    pattern $DMZ_IP - $PRZ_IP,
    TIMEOUT 300,
    DST_ANNO true
);

packet_classifier_from_prz :: Classifier(
    12/0806 20/0001, // ARP request
    12/0806 20/0002, // ARP reply
    12/0800, // IP
    -
);

packet_classifier_from_dmz :: Classifier(
    12/0806 20/0001, // ARP request
    12/0806 20/0002, // ARP reply
    12/0800, // IP
    - 
);

ip_classifier_from_prz :: IPClassifier(
    tcp,
    icmp type echo-request,
    icmp type echo-reply,
    -
);

ip_classifier_from_dmz :: IPClassifier(
    tcp,
    icmp type echo-request,
    icmp type echo-reply,
    -
);

//ARP
arp_req_prz :: ARPQuerier($PRZ_IP, 01:02:03:04:05:06);
arp_req_dmz :: ARPQuerier($DMZ_IP, 06:05:04:03:02:01);
arp_res_prz :: ARPResponder($PRZ_IP 10.0.0.0/24 01:02:03:04:05:06);
arp_res_dmz :: ARPResponder($DMZ_IP 100.0.0.0/24 06:05:04:03:02:01);

from_prz -> cnt_in1 -> packet_classifier_from_prz;
from_dmz -> cnt_in2 -> packet_classifier_from_dmz;

// ARP from PrZ
packet_classifier_from_prz[0] -> arp_req1 -> arp_res_prz -> to_prz;
packet_classifier_from_prz[1] -> arp_res1 -> [1]arp_req_prz;
packet_classifier_from_prz[2] -> Strip(14) -> CheckIPHeader -> ip_classifier_from_prz;
packet_classifier_from_prz[3] -> drop1 -> Discard;

// ARP from DmZ
packet_classifier_from_dmz[0] -> arp_req2 -> arp_res_dmz -> to_dmz;
packet_classifier_from_dmz[1] -> arp_res2 -> [1]arp_req_dmz;
packet_classifier_from_dmz[2] -> Strip(14) -> CheckIPHeader -> ip_classifier_from_dmz;
packet_classifier_from_dmz[3] -> drop2 -> Discard;

// TCP and ICMP handling
ip_classifier_from_prz[0] -> ipRewrite[0] -> [0]arp_req_dmz -> to_dmz;
ip_classifier_from_prz[1] -> icmp_rw_prz_to_dmz[0] -> [0]arp_req_dmz -> to_dmz;
ip_classifier_from_prz[2] -> drop1 -> Discard;

ip_classifier_from_dmz[0] -> ipRewrite[1] -> [0]arp_req_prz -> to_prz;
ip_classifier_from_dmz[1] -> icmp_rw_dmz_to_prz[0] -> [0]arp_req_prz -> to_prz;
ip_classifier_from_dmz[2] -> drop2 -> Discard;

DriverManager(
    pause, 
    print > /opt/pox/ext/results/napt.report  "
     =================== NAPT Report ===================
        Input Packet rate (pps): $(add $(cnt_in1.rate) $(cnt_in2.rate))
        Output Packet rate (pps): $(add $(cnt_out1.rate) $(cnt_out2.rate))

      Total # of   input packets: $(add $(cnt_in1.count) $(cnt_in2.count))
      Total # of  output packets: $(add $(cnt_out1.count) $(cnt_out2.count))
   
      Total # of   ARP  requests: $(add $(arp_req1.count) $(arp_req2.count))
      Total # of   ARP responses: $(add $(arp_res1.count) $(arp_res2.count))

      Total # of service packets: $(add $(cnt_in1.count) $(cnt_in2.count))
      Total # of    ICMP report:  $(add $(cnt_out1.count) $(cnt_out2.count))   
      Total # of dropped packets: $(add $(drop1.count) $(drop2.count))   
     =================================================
    " 
);
