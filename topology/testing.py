import topology


# def ping(client, server, expected, count=1, wait=1):

#     # TODO: What if ping fails? How long does it take? Add a timeout to the command!
#     cmd = f"ping {server} -c {count}  >/dev/null 2>&1; echo $?"
#     ret = client.cmd(cmd)
#     # TODO: Here you should compare the return value "ret" with the expected value
#     # (consider both failures
#     return True  # True means "everyhing went as expected"/
def ping(client, server, expected, count=1, wait=1,timeout=3):
    """
    Executes a ping command from a client to a server, while capturing packets on the specified interface.

    :param client: The client host from which the ping is sent.
    :param server: The target host to be pinged.
    :param interface: Network interface on which to capture packets.
    :param expected: Expected boolean result (True if expecting success, False otherwise).
    :param count: Number of ICMP packets to send.
    :param wait: Time in seconds to wait between packets.
    :param timeout: Total time in seconds to allow the ping command to run.
    :param pcap_file: Filename to save the captured packets.
    :return: True if the actual result matches the expected result, False otherwise.
    """
    # Build the tcpdump command to capture ICMP packets related to the ping
    # capture_cmd = f"tcpdump -i {interface} icmp and host {server} -w {pcap_file} &"
    # client.cmd(capture_cmd)

    # Build the ping command with timeout
    ping_cmd = f"ping -c {count} -W {wait} -w {timeout} {server.IP()} >/dev/null 2>&1; echo $?"
    

    # Execute the ping command
    ret = client.cmd(ping_cmd).strip()

    # Return True if the outcome matches what was expected, False otherwise
    success = (ret == "0" and expected) or (ret != "0" and not expected)
    if success:
        print(f"{client.name} ping to {server.name}: Expected {expected}, Result: Success")
    else:
        print(f"{client.name} ping to {server.name}: Expected {expected}, Result: Failure")

    return success

    
def curl(client, server, method="GET", payload="test", port=80, expected_code=200):
        """
        run curl for HTTP request. Request method and payload should be specified
        Server can either be a host or a string
        return True in case of success, False if not
        """

        if (isinstance(server, str) == 0):
            server_ip = str(server.IP())
        else:
            # If it's a string it should be the IP address of the node (e.g., the load balancer)
            server_ip = server

        # TODO: Specify HTTP method
        # TODO: Pass some payload (a.k.a. data). You may have to add some escaped quotes!
        # The magic string at the end reditect everything to the black hole and just print the return code
        cmd = f"curl -s -o /dev/null -w '%{{http_code}}' -X {method} -d '{payload}' http://{server_ip}:{port}"
        ret_code = client.cmd(cmd).strip()
        if int(ret_code) == expected_code:
            print(f"{client.name} curl to {server.name}:{port}: Expected HTTP {expected_code}, Result: Success")
            return True
        else:
            print(f"{client.name} curl to {server.name}:{port}: Expected HTTP {expected_code}, Result: Failure, Received: {ret_code}")
            return False
