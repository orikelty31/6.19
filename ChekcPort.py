
"""
Author : Ori Kelty
description:  Open Port Scanner using Scapy | Method: TCP SYN Scan (Three-Way Handshake)

How it works:
 Send a SYN packet to each port in the range
 If we receive SYN+ACK that means the port is OPEN  (a service is listening)
 If we receive RST or no reply that means the port is CLOSED / filtered
"""
import socket
from scapy.all import IP, TCP, sr1
import sys
import logging


# Constants
TIMEOUT = 0.5       # seconds to wait for a reply (adjust to your environment)
PORT_START = 20
PORT_END = 1024
OPEN_PORT = 0x12


def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def scan_port(target_ip, port):
    """
    Send a SYN packet to the given port.
    Returns True if the port is open (SYN+ACK received), False otherwise.
    """

    syn_pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
    response = sr1(syn_pkt, timeout=TIMEOUT, verbose=0)

    if response is None:
        logging.info("Port: " + str(port) + " On IP: " + str(target_ip) + " Is Not Responding")
        logging.info("-" * 50)
        return False  # No reply – port is closed or filtered

    tcp_layer = response.getlayer(TCP)
    if tcp_layer is None:
        logging.info("Port: " + str(port) + " On IP: " + str(target_ip) + " Is Closed")
        logging.info("-" * 50)
        return False

    # SYN+ACK (flags == 0x12) means the port is open
    if tcp_layer.flags == OPEN_PORT:
        # Send RST to politely close the half-open connection
        rst_pkt = IP(dst=target_ip) / TCP(dport=port, flags="R")
        sr1(rst_pkt, timeout=TIMEOUT, verbose=0)
        logging.info("Port: " + str(port) + " On IP: " + str(target_ip) + " Is Open!")
        logging.info("-" * 50)
        return True

    logging.info("Port: " + str(port) + " On IP: " + str(target_ip) + " Is Closed")
    logging.info("-" * 50)
    return False  # RST or any other response – port is closed


def scan_host(target_ip):
    """
    Scan ports PORT_START through PORT_END and print the open ones.
    """
    logging.info("-" * 50)
    logging.info("Started Checking Ports On IP: " + str(target_ip))
    logging.info("-" * 50)
    print("Starting To Check Open Ports")
    open_ports = []

    for port in range(PORT_START, PORT_END + 1):
        if scan_port(target_ip, port):
            open_ports.append(port)
            print("Port: " + str(port) + " | OPEN ")
    logging.info("Ports Checking Have Been Finished | The Open Ports Are: " + str(open_ports))
    logging.info("-" * 50)
    print("-" * 25)
    if open_ports:
        print("Found " + str(len(open_ports)) + " open port(s): " + str(open_ports))
        print("-" * 25)
    else:
        print("No open ports found in the scanned range.")
        print("-" * 25)


def main():
    if len(sys.argv) != 2:
        print("Usage: py  CheckPort.py <target-IP>")
        print("Example: py CheckPort.py 127.0.0.1")
        sys.exit(1)

    target = sys.argv[1]
    if not is_valid_ip(target):
        print("The IP That Was Entered Is Not Valid")
    else:
        scan_host(target)


if __name__ == "__main__":
    # Logging configuration
    logging.basicConfig(
        filename="CheckPort.log",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        filemode="w",
    )
    logging.info("Starting Assert Tests")
    assert is_valid_ip("127.0.0.1.1") is False, "Assertation Test Failed"
    assert 0 <= PORT_START <= 65535 and 0 <= PORT_END <= 65535, "One Of The Ports Is Lower Then 0 Or Higher Then 65535"
    assert PORT_START <= PORT_END, "Assertation Test Failed : Starting Port Must Be Lower Or Equal To The Ending Port"
    logging.info("All Asserts Passed!")
    main()
