
import socket, sys
import struct

ETH_P_ALL = 0x0003
eth_length = 14

def bytes_to_mac(bytesmac):
    return ":".join("{:02x}".format(x) for x in bytesmac)

def process_ip(packet):
    print("IP Packet")
    ip_header = packet[eth_length:20+eth_length]
    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl*4
    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])
    print("IP Src: "+s_addr)
    print("IP Dst: "+d_addr)
    if protocol == 1:
        process_icmp(packet, iph_length)


def process_icmp(packet, iph_length):
    print("ICMP Packet")
    icmp_header = packet[iph_length + eth_length:]
    icmph = struct.unpack("!BBHHH%ds" % (len(icmp_header)-8), icmp_header)
    icmp_type = icmph[0]
    icmp_code = icmph[1]
    icmp_id = icmph[2]
    icmp_seq = icmph[3]
    icmp_payload = icmph[4]
    print("Type: ", icmp_type)
    print("Code: ", icmp_code)
    
    if icmp_type == 8 and icmp_code == 0:
        print("Echo request")

    elif icmp_type == 0 and icmp_code == 0:
        print("Echo reply")

def start():    
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    except OSError as msg:
        print('Error'+str(msg))
        sys.exit(1)

    print('Socket created!')

    s.bind(('eth0',0))

    while True:
        (packet,addr) = s.recvfrom(65536)

        # eth_length = 14
        eth_header = packet[:14]

        eth = struct.unpack("!6s6sH",eth_header)

        print("MAC Dst: "+bytes_to_mac(eth[0]))
        print("MAC Src: "+bytes_to_mac(eth[1]))
        print("Type: "+hex(eth[2]))

        if eth[2] == 0x0800 :
            process_ip(packet)

start()