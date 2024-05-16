// ids
// 1. IPClassifier: classify HTTP traffic, allow ARP, ICMP, TCP signaling
// 2. HTTP Classifier: only allow POST and PUT
// 3. HTTP PUT: match against keywords


define($PORT1 ids-eth1, $PORT2 ids-eth2, $PORT3 ids-eth3)

// counters
cnt_in1, cnt_in2, cnt_out1, cnt_out2 :: AverageCounter; 
cnt_arp_req, cnt_arp_res, cnt_ip1, cnt_ip2, cnt_icmp, drop1, drop2 :: Counter;
cnt_http ,cnt_PUT, cnt_POST, cnt_INSP :: Counter;

// interfaces
from_switch :: FromDevice($PORT1, METHOD LINUX, SNIFFER false);
from_server :: FromDevice($PORT2, METHOD LINUX, SNIFFER false);
to_switch :: Queue -> cnt_out1 -> ToDevice($PORT1, METHOD LINUX);
to_server :: Queue -> cnt_out2-> ToDevice($PORT2, METHOD LINUX);
to_insp :: Queue -> ToDevice($PORT3, METHOD LINUX);

// classifier
packets_classifier_from_switch :: Classifier(12/0806 20/0001, 12/0800, -);

packets_classifier_from_server :: Classifier(12/0806 20/0002, 12/0800, -);

ip_classifier :: IPClassifier(proto icmp && icmp type echo, tcp, -);

http_classifier :: Classifier(
    // PUT
    66/505554,
    // POST
    66/504F5354,
    // others
    -
);

keywords_classfier :: Classifier(
    // i. cat/etc/passwd
    209/636174202F6574632F706173737764,
    // ii. cat/var/log/
    209/636174202F7661722F6C6F672F,
    // iii. INSERT
    208/494E53455254,
    // iv. UPDATE
    208/555044415445,
    // v. DELETE
    208/44454C455445,
    //others
    -
);

from_switch -> cnt_in1 -> packets_classifier_from_switch;
from_server -> cnt_in2 -> packets_classifier_from_server;

packets_classifier_from_switch[0] -> Print("ARP request, allow", -1) -> cnt_arp_req -> to_switch;
packets_classifier_from_switch[1] -> Strip(14) -> CheckIPHeader -> cnt_ip1 -> ip_classifier;
packets_classifier_from_switch[2] -> Print("Unwanted packets, discard", -1) -> drop1 -> Discard;

packets_classifier_from_server[0] -> Print("ARP response, allow", -1) -> cnt_arp_res -> to_server;
packets_classifier_from_server[1] -> Strip(14) -> CheckIPHeader -> Unstrip(14) -> cnt_ip2 -> to_switch;
packets_classifier_from_server[2] -> Print("Unwanted packets, discard", -1) -> drop2 -> Discard;

ip_classifier[0] -> Unstrip(14) -> Print("ICMP, allow") -> cnt_icmp -> to_server;
ip_classifier[1] -> Unstrip(14) -> Print("TCP signal, allow") -> to_server;
ip_classifier[2] -> Unstrip(14) -> cnt_http -> http_classifier;

s :: Search("\n\r\n\r")
s[0] -> keywords_classfier;
s[1] -> to_insp;

http_classifier[0] -> cnt_PUT -> s;
http_classifier[1] -> cnt_POST -> to_server;
http_classifier[2] -> cnt_INSP -> to_insp;

keywords_classfier[0] -> Print("keyword found - cat/etc/passwd", -1) -> cnt_INSP -> to_insp;
keywords_classfier[1] -> Print("keyword found - cat/var/log/", -1) -> cnt_INSP -> to_insp;
keywords_classfier[2] -> Print("keyword found - INSERT", -1) -> cnt_INSP -> to_insp;
keywords_classfier[3] -> Print("keyword found - UPDATE", -1) -> cnt_INSP -> to_insp;
keywords_classfier[4] -> Print("keyword found - DELETE", -1) -> cnt_INSP -> to_insp;
keywords_classfier[5] -> to_server;

DriverManager(
    pause, 
    print > /opt/pox/ext/results/ids.report  "
      =================== IDS Report ===================
      Input Packet rate (pps): $(add $(cnt_in1.rate) $(cnt_in2.rate))
      Output Packet rate (pps): $(add $(cnt_out1.rate) $(cnt_out2.rate))

      Total # of   input packets:  $(add $(cnt_in1.count)$(cnt_in2.count))
      Total # of  output packets:  $(add $(cnt_out1.count)$(cnt_out2.count))

      Total # of     IP  packets:  $(add $(cnt_ip1.count)$(cnt_ip2.count))
      Total # of    ARP  packets:  $(add $(cnt_arp_req.count)$(cnt_arp_res.count))
      Total # of   ICMP  packets:  $(cnt_icmp.count)
      Total # of   HTTP  packets:  $(cnt_http.count) 

      Total # of    PUT  packets:  $(cnt_PUT.count)
      Total # of   POST  packets:  $(cnt_POST.count) 


      Total # of to INSP packets:  $(cnt_INSP.count)
      Total # of dropped packets:  $(add $(drop1.count)$(drop2.count))
    =================================================
    " 
);