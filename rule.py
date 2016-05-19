from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
from utils import DNS, TCP, UDP, ICMP, ip_to_int


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
