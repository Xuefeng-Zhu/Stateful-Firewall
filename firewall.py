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


def load_rules(filename):
    rules = []
    with open(filename) as f:
        raw_config = f.readlines()
        for row in raw_config:
            row = row.strip('\n').split()
            if len(row):
                row = [item.upper() for item in row]
                rule = Rule(*row)
                rules.append(rule)
    return rules


def ip_to_int(ip):
    return struct.unpack('!I', socket.inet_aton(ip))[0]


class Rule:

    def __init__(self, action, protocol, address, port=None):
        self.action = action
        self.protocol = protocol

        if protocol == DNS:
            self.domain = address
        else:
            self._set_address(address)
            self._set_port(port)

    def _set_address(self, address):
        if address == 'ANY' or len(address) == 2:
            self.address = address
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


class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        # TODO: Load the firewall rules (from rule_filename) here.
        print 'I am supposed to load rules from %s, but I am feeling lazy.' % \
            config['rule']

        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        # TODO: Also do some initialization if needed.

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        pass

    # TODO: You can add more methods as you want.

# TODO: You may want to add more classes/functions as well.
