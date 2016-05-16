#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
import socket
import struct

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

    rules.reverse()
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

            ip = ip >> suffix
            self.address = (ip, suffix)

    def _set_port(self, port):
        if port == 'ANY':
            self.port = port
        else:
            try:
                self.port = int(port)
            except ValueError:
                self.port = map(int, port.split('-'))

    def match_pkt(self, pkt_info):
        if pkt_info.protocol == self.protocol:
            if self.protocol == TCP or self.protocol == UDP:
                return self._match_tcp_udp(pkt_info)
            elif self.protocol == ICMP:
                return self._match_icmp(pkt_info)
        elif self.protocol == DNS and pkt_info.valid_dns:
            return self._match_dns(pkt_info)

        return False

    def _match_tcp_udp(self, pkt_info):
        if self._match_address(pkt_info):
            if pkt_info.pkt_dir == PKT_DIR_INCOMING:
                port = pkt_info.src_port
            elif pkt_info.pkt_dir == PKT_DIR_OUTGOING:
                port = pkt_info.dst_port

            if self.port == 'ANY':
                return True
            elif isinstance(self.port, list):
                return port >= self.port[0] and port <= self.port[1]
            else:
                return port == self.port

        return False

    def _match_icmp(self, pkt_info):
        if self._match_address(pkt_info):
            if self.port == 'ANY':
                return True
            else:
                return pkt_info.icmp_type == self.port

        return False

    def _match_dns(self, pkt_info):
        if self.domain.find('*') == 0:
            return pkt_info.qname.endswith(self.domain[1:])

        return pkt_info.qname == self.domain

    def _match_address(self, pkt_info):
        if pkt_info.pkt_dir == PKT_DIR_INCOMING:
            address = pkt_info.src_ip
        elif pkt_info.pkt_dir == PKT_DIR_OUTGOING:
            address = pkt_info.dst_ip

        if self.address == 'ANY':
            return True
        elif isinstance(self.address, list):
            for addr_range in self.address:
                if address >= addr_range[0] and address <= addr_range[1]:
                    return True
        else:
            return (address >> self.address[1]) == self.address[0]


class PacketInfo:

    PROTOCOL_MAP = {
        1: ICMP,
        6: TCP,
        17: UDP
    }

    def __init__(self, pkt_dir, pkt):
        self.pkt = pkt
        self.pkt_dir = pkt_dir
        self.header_length = (ord(pkt[0]) & 7) * 4
        self.src_ip = ip_to_int(pkt[12:16], True)
        self.dst_ip = ip_to_int(pkt[16:20], True)
        self.inner_packet = self.pkt[self.header_length:]
        self._set_protocol()
        self._set_inner_field()
        self._set_dns_field()

    def _set_protocol(self):
        protocol_id = ord(self.pkt[9:10])
        self.protocol = self.PROTOCOL_MAP.get(protocol_id)

    def _set_inner_field(self):
        if self.protocol == UDP or self.protocol == TCP:
            self.src_port, = struct.unpack('!H', self.inner_packet[0:2])
            self.dst_port, = struct.unpack('!H', self.inner_packet[2:4])
        elif self.protocol == ICMP:
            self.icmp_type = ord(self.pkt[0:1])

    def _set_dns_field(self):
        self.valid_dns = False
        if self.protocol == UDP and self.dst_port == 53:
            dns_packet = self.inner_packet[8:]
            self.qd_count, = struct.unpack('!H', dns_packet[4:6])

            if self.qd_count == 1:
                content = dns_packet[12:]
                end_index = self._set_dns_qname(content)
                self.qtype = content[end_index + 1:end_index + 3]
                self.qtype, = struct.unpack('!H', self.qtype)
                self.qclass = content[end_index + 3:end_index + 5]
                self.qclass, = struct.unpack('!H', self.qclass)
                if ((self.qtype == 1 or self.qtype == 28) and
                        self.qclass == 1):
                    self.valid_dns = True

    def _set_dns_qname(self, question):
        qname = []
        index = 1
        byte = ord(question[index])
        while byte != 0:
            if byte == 6 or byte == 3:
                qname.append('.')
            else:
                qname.append(question[index])
            index += 1
            byte = ord(question[index])

        self.qname = ''.join(qname).upper()
        return index


class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        self.geodb = load_geodb()
        self.rules = load_rules(config['rule'], self.geodb)

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        pkt_info = PacketInfo(pkt_dir, pkt)
        allow_pass = True

        for rule in self.rules:
            if rule.match_pkt(pkt_info):
                allow_pass = rule.action == 'PASS'
                break

        print 'PASS' if allow_pass else 'DROP'
        if allow_pass:
            if pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send_ip_packet(pkt)
            elif pkt_dir == PKT_DIR_OUTGOING:
                self.iface_ext.send_ip_packet(pkt)

    def _get_matched_rule(self, pkt_info):
        for rule in self.rules:
            if rule.match_pkt(pkt_info):
                return rule
