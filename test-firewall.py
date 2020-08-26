#!/usr/bin/env python
#
# Author: Matthew Rasa
# E-mail: mrasa3@gatech.edu
#

from mininet.net import Mininet
from mininet.node import CPULimitedHost, RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
from argparse import ArgumentParser
import importlib
import subprocess as sp
import sys
import time
firewall_topo = importlib.import_module("firewall-topo")

def monitor_ps(ps, timeout=None):
    """
    Wait <timeout> seconds for process <ps> to finish.

    Returns the process return code if it finished, or None on timeout.
    """
    tend = time.time() + timeout if timeout is not None else sys.maxint
    while time.time() < tend:
        rs = ps.poll()
        if rs is not None:
            return rs
        time.sleep(0.01)
    return None

def test_cmd(host, cmd, timeout=None):
    """
    Run <cmd> on the <host> and test that it completed successfully within
    <timeout> seconds.

    Returns true if the command succeeded, false otherwise.
    """
    ps = host.popen(cmd)
    rs = monitor_ps(ps, timeout)
    if rs is None:
        ps.kill()
        return False
    return rs == 0

def host_ip(host):
    """ Return the IP for the given <host>. """
    return host.cmd('ip addr show {}-eth1 | awk \'/inet / {{ print $2 }}\' | cut -d\'/\' -f1'.format(host.name, host.name), stdout=sp.PIPE).strip()

def print_result(testcase, passed):
    """ Print test case result. """
    print '{:<6}{}'.format('{}:'.format(testcase), "allowed" if passed else "blocked")

def main():
    parser = ArgumentParser(description='Test the connection between two hosts')
    parser.add_argument('sender', help='Sending host')
    parser.add_argument('receiver', help='Receiving host')
    parser.add_argument('port', type=int, help='port number to test')
    parser.add_argument('--timeout', type=int, default=2, help='timeout value for tests [default: %(default)s seconds]')
    args = parser.parse_args()

    topo = firewall_topo.FWTopo()
    net = Mininet(topo=topo, link=TCLink, controller=RemoteController, autoSetMacs=True)

    net.start()
    sender = net.get(args.sender)
    receiver = net.get(args.receiver)
    receiver_ip = host_ip(receiver)

    # Start servers in the background
    receiver.cmd("python test-tcp-server.py {} {} &".format(receiver_ip, args.port))
    receiver.cmd("python test-udp-server.py {} {} &".format(receiver_ip, args.port))

    # Test clients
    print_result('ICMP', test_cmd(sender, "ping -c 1 -w {} {}".format(args.timeout, receiver_ip)))
    print_result('TCP', test_cmd(sender, "python test-tcp-client.py {} {}".format(receiver_ip, args.port), args.timeout))
    print_result('UDP', test_cmd(sender, "python test-udp-client.py {} {}".format(receiver_ip, args.port), args.timeout))

if __name__ == '__main__':
    main()