#!/bin/python

from enum import Enum
import utils
import pytuntap as tt
import parse
import sys
import utils
import tcp
import time
import traceback


class AF(Enum):
    INET = 0  # Use IP protocol on Internet layer


class SOCK(Enum):
    STREAM = 0
    DGRAM = 1


AF_INET = AF.INET
SOCK_STREAM = SOCK.STREAM
SOCK_DGRAM = SOCK.DGRAM


class Socket:
    def __init__(self, address_format: AF, sock_type: SOCK):
        # lol, this is pretty useless. Just wanted it to be just like built-in socket
        if address_format != AF_INET:
            utils.pprint(
                'IP (AF_INET) is the only currently supported network protocol')
            return
        if sock_type != SOCK_STREAM:
            utils.pprint(
                'TCP (SOCK_STREAM) is the only supported transport protocol')
            return

    def bind(self, server_address: tuple):
        self.ip = server_address[0]
        self.port = server_address[1]

        # Create a Tun device (virtual interface at layer 3)
        self.tun = tt.TunTap('Tun', 'tun2')
        self.tun.config(self.ip, '255.255.255.0')

        # List of TCP connections
        self.conns = []

    def listen(self):
        pass

    def accept(self):
        # Command-line options
        verbose = '-v' in sys.argv
        surpress = '-s' in sys.argv

        buff = self.tun.read(512)

        # Parse IPv4 packet
        iparse = parse.ip(buff)

        # Check validity of packet
        if iparse is None:  # Not a valid IPv4 packet
            return
        if iparse.prtcl != 6:  # TCP protocol
            if surpress:
                return
            print(f'\n\33[1mRecived \33[35m{utils.prtcls[iparse.prtcl]}\33[39m packet,'
                  ' ignoring...\33[0m (you can use -v to display all IPv4 packets)')
            return

        # IP payload (iclued all of TCP)
        idata = iparse.data
        # Parse TCP packet
        tcparse = parse.tcp(idata)

        # Some pretty prints
        utils.print_pac(iparse, tcparse)

        # Make the flags from the packet into a Flags object and print
        flags = utils.Flags(tcparse.flags)
        print(flags)

        # ------------ Manage TCP connections ---------------
        quad = tcp.Quad(iparse.srcip, tcparse.src_port,
                        iparse.dstip, tcparse.dst_port)

        # Check if connection already exists, if not, create one
        conn_exists = False
        conn = None
        for con in self.conns:
            if con.quad == quad:  # The packet is for an existing connection
                conn_exists = True
                conn = con
                break
        if not conn_exists:  # Start a new connection
            conn = tcp.Connection(self.tun)
            conn.open(quad)
            self.conns.append(conn)  # Add connection to connections list

        conn.recv(tcparse)
