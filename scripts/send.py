#!/usr/bin/python
import socket
import random
import os
import struct
import fcntl
import time

# checksum functions needed for calculation checksum
def checksum(msg):
    s = 0
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = (ord(msg[i]) << 8) + ( ord(msg[i+1]) )
        s = s + w

    s = (s>>16) + (s & 0xffff)
    #s = s + (s >> 16)    #complement and mask to 4 byte short
    s = ~s & 0xffff

    return s

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])


def eth_header(dst, src, proto=0x0800):
    dst_bytes = "".join([x.decode('hex') for x in dst.split(":")])
    src_bytes = "".join([x.decode('hex') for x in src.split(":")])
    return dst_bytes + src_bytes + struct.pack("!H", proto)

def ip_header(src,dst,ttl,proto,id=0):

    # now start constructing the packet
    packet = ''
    # ip header fields
    ihl = 5
    version = 4
    tos = 128
    tot_len = 20 + 20   # python seems to correctly fill the total length, dont know how ??
    frag_off = 0
    if proto == "tcp":
        proto = socket.IPPROTO_TCP
    elif proto == "udp":
        proto = socket.IPPROTO_UDP
    else:
        print "proto unknown"
        return
    check = 10  # python seems to correctly fill the checksum
    saddr = socket.inet_aton ( src )  #Spoof the source ip address if you want to
    daddr = socket.inet_aton ( dst )

    ihl_version = (version << 4) + ihl

    # the ! in the pack format string means network order
    ip_header = struct.pack('!BBHHHBBH4s4s' , ihl_version, tos, tot_len, id, frag_off, ttl, proto, check, saddr, daddr)
    return ip_header

def tcp_header(src,dst,sport,dport):

    # tcp header fields
    source = sport #sourceport
    dest = dport  # destination port
    seq = 0
    ack_seq = 0
    doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
    #tcp flags
    fin = 0
    syn = 1
    rst = 0
    psh = 0
    ack = 0
    urg = 0
    window = socket.htons (5840)    #   maximum allowed window size
    check = 0
    urg_ptr = 0

    offset_res = (doff << 4) + 0
    tcp_flags = fin + (syn << 1) + (rst << 2) + (psh <<3) + (ack << 4) + (urg << 5)

    # the ! in the pack format string means network order
    tcp_header = struct.pack('!HHLLBBHHH' , source, dest, seq, ack_seq, offset_res, tcp_flags,  window, check, urg_ptr)

    # pseudo header fields
    source_address = socket.inet_aton( src )
    dest_address = socket.inet_aton(dst)
    placeholder = 0
    proto = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)

    psh = struct.pack('!4s4sBBH' , source_address , dest_address , placeholder , proto , tcp_length)
    psh = psh + tcp_header

    tcp_checksum = checksum(psh)

    # make the tcp header again and fill the correct checksum
    tcp_header = struct.pack('!HHLLBBHHH' , source, dest, seq, ack_seq, offset_res, tcp_flags,  window, tcp_checksum , urg_ptr)

    # final full packet - syn packets dont have any data
    return tcp_header

def getInterfaceName():
    #assume it has eth0

    return [x for x in os.listdir('/sys/cla'
                                  'ss/net') if "eth0" in x][0]

def send_n(s, packet, n):
    i = 0
    for _ in range(n):
        s.send(packet)
        # Slowed down:
        # Packet traffic must be slowed down for frequent capture of estimates, because estimate retrieval by the controller takes multiple seconds
        #time.sleep(4)
        # Full speed:
        time.sleep(0.0003)

def create_packet_ip_tcp(eth_h, src_ip, dst_ip, sport, dport):
    return eth_h + ip_header(src_ip, dst_ip, 64, "tcp",1) + tcp_header(src_ip, dst_ip, sport, dport)

def get_random_flow():
    src_ip = socket.inet_ntoa(struct.pack("!I", random.randint(167772160, 4261412864))) # between 10.0.0.0 and 254.0.0.0
    dst_ip = socket.inet_ntoa(struct.pack("!I", 167772418)) # 10.0.1.2
    sport = 1 # ports are fixed so uniqueness is defined by src IP only 
    dport = 80
    return (src_ip, dst_ip, sport, dport)

def get_flow(i):
    src_ip = socket.inet_ntoa(struct.pack("!I", 167772419 + i))
    dst_ip = socket.inet_ntoa(struct.pack("!I", 167772418)) # 10.0.1.2
    sport = 1 # ports are fixed so uniqueness is defined by src IP only 
    dport = 80
    return (src_ip, dst_ip, sport, dport)

def generate_test(n_packets, n_source_ips):

    flows = {}

    # n_source_ips: number of unique source IPs
    # n_packets: packets sent per source IP

    for i in range(n_source_ips):
        flow = get_random_flow()
        while flow in flows:
            flow = get_random_flow()
        flows[flow] = n_packets

    return flows

def main(n_packets, n_source_ips):

    send_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    intf_name = getInterfaceName()
    send_socket.bind((intf_name, 0))

    eth_h = eth_header("00:00:0a:00:01:02", "00:00:0a:00:01:01") # dst, src
    flows = generate_test(n_packets, n_source_ips)

    for flow, n in flows.items():
        #start = time.time()
        packet = create_packet_ip_tcp(eth_h, *flow)
        send_n(send_socket, packet, n)
        #end = time.time()
        #speed = len(packet) * n / (end - start) / 10**6
        #print("Sending packets at {:f} MB/s".format(speed))

    send_socket.close()


if __name__ == "__main__":

    import argparse
    parser = argparse.ArgumentParser()

    parser.add_argument('--n-pkt', type=int, required=False, default=1) # Number of packets per source IP
    parser.add_argument('--n-src', type=int, required=False, default=10) # Number of different source IPs
    args= parser.parse_args()

    main(args.n_pkt, args.n_src)


