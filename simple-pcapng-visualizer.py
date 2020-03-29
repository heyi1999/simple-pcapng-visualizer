import sys
import socket
import binascii
import networkx as nx
import matplotlib.pyplot as plt
from pcapng import FileScanner
from pcapng import blocks


def get_pcap_packet_blocks(filename):

    packet_blocks = []
    with open(filename, 'rb') as fp:
        scanner = FileScanner(fp)
        for block in scanner:
            if isinstance(block, blocks.EnhancedPacket):
                packet_blocks.append(block)

    return packet_blocks


class EthernetFrame():
    def __init__(self, packet_bytes):
        self._parse_packet(packet_bytes)
    
    def _parse_packet(self, packet_bytes):
        self.dst = packet_bytes[0:6]
        self.src = packet_bytes[6:12]
        self.type = packet_bytes[12:14]
        self.data = packet_bytes[14:]
    
    def __str__(self):
        return 'EthernetFrame:\nDestination: {}\nSource: {}\nType: {}\nData: {}'.format(self.dst, self.src, self.type, self.data)
    
def get_eth_frame(packet_block):

    if not packet_block.interface.link_type == 1:
        return None
    
    packet_data = packet_block.packet_data
    ethernet_frame = EthernetFrame(packet_data)
    return ethernet_frame



class IPv4_Packet():
    def __init__(self, data):
        self._parse_packet(data)
    
    
    def _parse_packet(self, data):
        self.version = data[0] >> 4
        
        # extract header length (number of 32-bit words in the header)
        ihl     = data[0] & int('00001111', 2)
        header_size = ihl * 4 # so multiply by 4 to get the number of bytes
        
        # get the total size of the packet (header + data)
        total_size = int(binascii.hexlify(data[2:4]), 16)
        
        # set the internal values (this also drops the padding from the internet frame)
        self.header = data[0:header_size]
        self.data = data[header_size:total_size]
        self.protocol = data[9]
        self.src_ip = data[12:16]
        self.dst_ip = data[16:20]

        
def get_ipv4_packet(ethernet_frameethernet_frame):
    # Check that the ethernet frame has tpye 0x0800 and is IPv4
    if not ethernet_frame.type == b'\x08\x00':
        return None

    ipv4_packet = IPv4_Packet(ethernet_frame.data)
    return ipv4_packet



if __name__ == '__main__':
    FILENAME = sys.argv[1]
    OUTPUT = sys.argv[2]

    if FILENAME is None:
        print('Pcapng file not found!')
        exit(1)

    if OUTPUT is None:
        OUTPUT = 'output'
    
    pbs = get_pcap_packet_blocks(FILENAME)

    with open("output.txt",'w') as f: # write in text mode
        for count, pb in enumerate(pbs):
            ethernet_frame = get_eth_frame(pb)
            ipv4_packet = get_ipv4_packet(ethernet_frame)

            # only check for ipv4 packges
            if not ethernet_frame.type == b'\x08\x00':
                continue

            f.write('{} {}\n'.format(socket.inet_ntoa(ipv4_packet.src_ip), socket.inet_ntoa(ipv4_packet.dst_ip)))

    G = nx.read_edgelist('output.txt', create_using=nx.Graph())

    nx.draw(G, with_labels=True)

    fig = plt.gcf()
    fig.set_size_inches(50, 15, forward=True)

    plt.savefig("{}.svg".format(OUTPUT), dpi=1000)


