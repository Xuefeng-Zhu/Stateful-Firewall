#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
from packet_info import PacketInfo
from utils import load_geodb, load_rules


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
