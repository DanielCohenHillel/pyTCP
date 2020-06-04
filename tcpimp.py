#!/bin/python

import pytuntap as tt
import parse
import sys
import utils
import tcp
import time
import traceback

# Create a Tun device (virtual interface at layer 3)
tun = tt.TunTap('Tun', 'tun2')
tun.config('192.168.0.123', '255.255.255.0')

# List of TCP connections
conns = []
try:
    while True:
        # Command-line options
        verbose = '-v' in sys.argv
        surpress = '-s' in sys.argv

        # Read incoming packets
        buff = tun.read(512)

        # Parse IPv4 packet
        iparse = parse.ip(buff)

        # Check validity of packet
        if iparse is None:  # Not a valid IPv4 packet
            continue
        if iparse.prtcl != 6:  # TCP protocol
            if surpress:
                continue
            print(f'\n\33[1mRecived \33[35m{utils.prtcls[iparse.prtcl]}\33[39m packet,'
                  ' ignoring...\33[0m (you can use -v to display all IPv4 packets)')
            continue

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
        for con in conns:
            if con.quad == quad:  # The packet is for an existing connection
                conn_exists = True
                conn = con
                break
        if not conn_exists:  # Start a new connection
            conn = tcp.Connection(tun)
            conn.open(quad)
            conns.append(conn)  # Add connection to connections list

        conn.recv(tcparse)


except Exception as e:
    print('\n\33[1mExiting...\33[0m\n', e)
    traceback.print_exc()
    tun.close()
finally:
    print('\n\33[1mExiting but its good :)\33[0m')
    for conn in conns:
        conn.close()
    tun.close()
    print('\33[1m', '-'*30, 'Connections', '-'*30, '\33[0m')
    print('\n'.join([str(conn.quad) for conn in conns]))
