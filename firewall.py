#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket
import struct


# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries.

TCP = 'TCP'
UDP = 'UDP'
DNS = 'DNS'
ICMP = 'ICMP'


def load_geodb(filename='geoipdb.txt'):
    geo_data = {}
    with open(filename) as f:
        database = f.readlines()
        for row in database:
            start, end, country = row.strip('\n').split()
            record = geo_data.setdefault(country, [])
            ip_range = (ip_to_int(start), ip_to_int(end))
            record.append(ip_range)
    return geo_data


def load_rules(filename, geodb):
    rules = []
    with open(filename) as f:
        raw_config = f.readlines()
        for row in raw_config:
            row = row.strip('\n').split()
            if len(row):
                row = [item.upper() for item in row]
                rule = Rule(*row, geodb=geodb)
                rules.append(rule)
    return rules


def ip_to_int(ip, is_hex=False):
    if not is_hex:
        ip = socket.inet_aton(ip)

    return struct.unpack('!I', ip)[0]


class Rule:

    def __init__(self, action, protocol, address, port=None, geodb=None):
        self.action = action
        self.protocol = protocol

        if protocol == DNS:
            self.domain = address
        else:
            self._set_address(address, geodb)
            self._set_port(port)

    def _set_address(self, address, geodb):
        if address == 'ANY':
            self.address = address
        elif len(address) == 2:  # country code
            self.address = geodb[address]
        else:
            address = address.split('/')
            ip = ip_to_int(address[0])
            suffix = 0

            if len(address) == 2:
                suffix = 32 - int(address[1])

            self.address = (ip, suffix)

    def _set_port(self, port):
        if port == 'ANY':
            self.port = 'ANY'
        else:
            try:
                self.port = int(port)
            except ValueError:
                self.port = map(int, port.split('-'))


class Packet:

    PROTOCOL_MAP = {
        1: ICMP,
        6: TCP,
        17: UDP
    }

    def __init__(self, pkt_dir, pkt):
        self.pkt = pkt
        self.pkt_dir = pkt_dir
        self.header_length = struct.unpack('!B', pkt[1:2]) * 4
        self.src_ip = ip_to_int(pkt[12:16], True)
        self.dst_ip = ip_to_int(pkt[16:20], True)
        self.inner_packet = self.pkt[self.header_length:]
        self._set_protocol()
        self._set_inner_field()
        self.set_dns_field()

    def _set_protocol(self):
        protocol_id = struct.unpack('!B', self.pkt[9:10])
        self.protocol = self.PROTOCOL_MAP.get(protocol_id)

    def _set_inner_field(self):
        if self.protocol is UDP or self.protocol is TCP:
            self.src_port = struct.unpack('!H', self.inner_packet[0:2])
            self.dst_port = struct.unpack('!H', self.inner_packet[2:4])
        elif self.protocol is ICMP:
            self.type = struct.unpack('!B', self.pkt[0:1])

    def _set_dns_field(self):
        if self.protocol is UDP and self.dst_port == 53:
            dns_packet = self.inner_packet[8:]
            self.qd_count = struct.unpack('!H', dns_packet[4:5])

            self.valid_dns = False
            if self.qd_count == 1:
                content = dns_packet[12:]
                end_index = self._set_dns_qname(content)
                self.qtype = content[end_index + 1:end_index + 3]
                self.qtype = struct.unpack('!H', self.qtype)
                self.qclass = content[end_index + 4:end_index + 6]
                self.qclass = struct.unpack('!H', self.qclass)
                if ((self.qtype == 1 or self.qtype == 28) and
                        self.qclass == 1):
                    self.valid_dns = True

    def _set_dns_qname(self, question):
        index = 1
        qname = []
        while question[index] != 0x00:
            byte = question[index]
            if byte == 0x06 or byte == 0x03:
                qname.append('.')
            else:
                qname.append(chr(byte))
            index += 1

        self.qname = ''.join(qname)
        return index


class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        self.geodb = load_geodb()
        self.rules = load_rules(config['rule'], self.geodb)

        # TODO: Also do some initialization if needed.

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        pass

    # TODO: You can add more methods as you want.

# TODO: You may want to add more classes/functions as well.
