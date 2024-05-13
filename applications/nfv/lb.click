// Load Balancer: 
// 1. ARP request: generate ARP reply from ARPResponder
// 2. ARP response: ARPQuerier
// 3. IP packets: load balancing
// 4. others: discard

define($VIRTUAL_SERVICE_IP 100.0.0.45)
define($VIRTUAL_MAC 12:34:56:12:34:56)
define($PORT1 lb1-eth1, $PORT2 lb1-eth2)

elementclass L2Forwarder {$port|
	input
	->Strip(14)
	->CheckIPHeader
	->Unstrip(14)
	->output
}

// counters
cnt_in1, cnt_in2, cnt_out1, cnt_out2 :: AverageCounter; 
arp_req1, arp_req2, arp_res1, arp_res2 :: Counter;
cnt_serv1, cnt_serv2, cnt_icmp1, cnt_icmp2 :: Counter;
drop1, drop2, drop3, drop4 :: Counter;

// directions:
// 1. toward servers
from_ids :: FromDevice($PORT2, METHOD LINUX, SNIFFER false);
to_ws :: ToDevice($PORT1, METHOD LINUX);
// 2. toward clients
from_ws :: FromDevice($PORT1, METHOD LINUX, SNIFFER false);
to_ids :: ToDevice($PORT2, METHOD LINUX);


// queues
to_ids_queue :: Queue(1024) -> Print("to client") -> cnt_out1 -> to_ids;
to_ws_queue :: Queue(1024) -> Print("to server") -> cnt_out2 -> to_ws;

// classifier
from_ws -> Print("packet from server", -1) -> cnt_in1 -> classifier_to_ids:: Classifier(
    12/0806 20/0001, //ARP request
    12/0806 20/0002, //ARP response
    12/0800, //IP
    - //others
    );
from_ids -> Print("packet from client", -1) -> cnt_in2 -> classifier_to_ws :: Classifier(12/0806 20/0001, 12/0806 20/0002, 12/0800, -);

// IP pipelines toward servers: 
classifier_to_ws[2] -> Strip(14) -> CheckIPHeader -> to_ws_ip :: IPClassifier(
    //TCP
    tcp dst port 80 and dst ip $VIRTUAL_SERVICE_IP,
    //ICMP
    icmp && icmp type echo and dst ip $VIRTUAL_SERVICE_IP,
    //others
    -
    );

// IP pipelines toward clients:
classifier_to_ids[2] -> Strip(14) -> CheckIPHeader -> to_ids_ip :: IPClassifier(
    // TCP
    tcp and src port 80,
    // ICMP response 
    icmp type echo and dst $VIRTUAL_SERVICE_IP,
    //others
    -
    );

// IP rewrite

ipRewrite :: IPRewriter (roundRobin);

roundRobin :: RoundRobinIPMapper(
    100.0.0.45 - 100.0.0.40 - 0 1,
    100.0.0.45 - 100.0.0.41 - 0 1,
    100.0.0.45 - 100.0.0.42 - 0 1);

ipRewrite[0] -> ipPacket_to_ws;
ipRewrite[1] -> ipPacket_to_ids;

ipPacket_to_ids :: GetIPAddress(16) -> CheckIPHeader -> [0]arp :: ARPQuerier($VIRTUAL_SERVICE_IP, $VIRTUAL_MAC) -> to_ids_queue;
ipPacket_to_ws :: GetIPAddress(16) -> CheckIPHeader -> [0]arp :: ARPQuerier($VIRTUAL_SERVICE_IP, $VIRTUAL_MAC) -> to_ws_queue;

// ARP 
classifier_to_ids[0] -> arp_req1 -> ARPResponder($VIRTUAL_SERVICE_IP $VIRTUAL_MAC) -> to_ids_queue;
classifier_to_ids[1] -> arp_res1 -> [1]arp :: ARPQuerier($VIRTUAL_SERVICE_IP, $VIRTUAL_MAC);

classifier_to_ws[0] -> arp_req2 -> ARPResponder($VIRTUAL_SERVICE_IP $VIRTUAL_MAC) -> to_ws_queue;
classifier_to_ws[1] -> arp_res2 -> [1]arp :: ARPQuerier($VIRTUAL_SERVICE_IP, $VIRTUAL_MAC);

//ICMP
to_ids_ip[1] -> cnt_icmp1 -> ICMPPingResponder -> ipPacket_to_ids;
to_ws_ip[1] -> cnt_icmp2 -> ICMPPingResponder -> ipPacket_to_ws;

// IP
classifier_to_ids[2] -> cnt_serv1 -> Strip(14) -> CheckIPHeader -> to_ids_ip;
classifier_to_ws[2] -> cnt_serv2 -> Strip(14) -> CheckIPHeader -> to_ws_ip;

// TCP
to_ids_ip[0] -> [0]ipRewrite;
to_ws_ip[0] -> [0]ipRewrite;

// discard:
classifier_to_ids[3] -> Print("Non IP packet, discard") -> drop1 -> Discard;
classifier_to_ws[3] -> Print("Non IP packet, discard") -> drop2 -> Discard;
to_ids_ip[2] - Print("unwanted IP packet", discard") -> drop3 -> Discard;
to_ws_ip[2] - Print("unwanted IP packet", discard") -> drop4 -> Discard;


DriverManager(pause, print > ../../results/lb1.report  "
     =================== LB1 Report ===================
        Input Packet rate (pps): $(add $(cnt_in1.rate) $(cnt_in2.rate))
        Output Packet rate (pps): $(add $(cnt_out1.rate) $(cnt_out2.rate))
        
        Total # of   input packets: $(add $(cnt_in1.count) $(cnt_in2.count))
        Total # of  output packets: $(add $(cnt_out1.count) $cnt_out2.count))
      
        Total # of   ARP  requests: $(add $(arp_req1.count) $(arp_req2.count))
        Total # of   ARP responses: $(add $(arp_res1.count) $(arp_res2.count))
      
        Total # of service packets: $(add $(cnt_serv1.count) $(cnt_serv2.count))
        Total # of    ICMP report:  $(add $(cnt_icmp1.count) $(cnt_icmp2.count))
        Total # of dropped packets: $(add $(drop1.count) $(drop2.count) $(drop3.count) $(drop4.count))  

     =================================================
     " );