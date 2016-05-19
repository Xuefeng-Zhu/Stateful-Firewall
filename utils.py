import socket
import struct
from rule import Rule

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
