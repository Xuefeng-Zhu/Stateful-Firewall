from utils import TCP, UDP, ICMP, ip_to_int
import struct


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
