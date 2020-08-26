#!/usr/bin/python
# CS 6250 Summer 2020 - Project 4 - SDN Firewall
# build atlas-v13

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import packets
from pyretic.core import packet

def make_firewall_policy(config):

    # The rules list contains all of the individual rule entries.
    rules = []

    for entry in config:

	# corner case: empty rule
	if entry['macaddr_src'] =='-' and entry['macaddr_dst'] =='-' and entry['ipaddr_src'] =='-' and entry['ipaddr_dst'] =='-' and entry['port_src'] =='-' and entry['port_dst'] =='-' and entry['protocol'] =='-' and entry['ipproto'] =='-':
	    print "emtrpy entered"
	    continue
	
	rule = match(ethtype=packet.IPV4)
        # check mac
        if entry['macaddr_src'] != '-':
            rule &= match(srcmac=EthAddr(entry['macaddr_src']))
        if entry['macaddr_dst'] != '-':
            rule &= match(dstmac=EthAddr(entry['macaddr_dst']))
        # check ip
        if entry['ipaddr_src'] != '-':
            rule &= match(srcip=IPAddr(entry['ipaddr_src']))
        if entry['ipaddr_dst'] != '-':
            rule &= match(dstip=IPAddr(entry['ipaddr_dst']))
	# check port
        if entry['port_src'] != '-':
            rule &= match(srcport=int(entry['port_src']))
        if entry['port_dst'] != '-':
            rule &= match(dstport=int(entry['port_dst']))
	# check protocol
        if entry['protocol'] != '-':
            if entry['protocol'] == 'T':
                rule &= match(protocol=packet.TCP_PROTO)
            elif entry['protocol'] == 'U':
                rule &= match(protocol=packet.UDP_PROTO)
            elif entry['protocol'] == 'I':
                rule &= match(protocol=packet.ICMP_PROTO)
	    elif entry['protocol'] == 'O':
	        rule &= match(protocol=int(entry['ipproto']))
            elif entry['protocol'] == 'B':
                ruleT = rule & match(protocol=packet.UDP_PROTO)
                rules.append(ruleT)
                rule &= match(protocol=packet.TCP_PROTO)

        rules.append(rule)
        pass
    
    allowed = ~(union(rules)) 

    return allowed
	


