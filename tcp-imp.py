#!/bin/python

import pytuntap as tt
import parse
import sys
# import tcp
import utils
import tcp
# from collections.abc import Iterable
restr = '''\
45 00 00 54 ab b3 40 00 40 01 0d 29 c0 a8 00 7b\
c0 a8 00 01 08 00 11 31 00 04 00 0c ce 57 d2 5e\
00 00 00 00 7c 35 0b 00 00 00 00 00 10 11 12 13\
14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23\
24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33\
34 35 36 37\
'''
restr = '''\
45 00 00 3c 6d 62 40 00 40 06 4b 15 c0 a8 00 7b\
c0 a8 00 79 e9 9a 00 50 51 61 80 88 00 00 00 00\
a0 02 fa f0 0f 92 00 00 02 04 05 b4 04 02 08 0a\
4e 42 b1 21 00 00 00 00 01 03 03 07\
'''
res = bytes.fromhex(restr)
print(res)

tun = tt.TunTap('Tun', 'tun2')
tun.config('192.168.0.123', '255.255.255.0')
try:
    conns = []
    for _ in range(510000):
        # Command options
        verbose = '-v' in sys.argv
        surpress = '-s' in sys.argv

        buff = tun.read(512)
        dbuf = parse.ip(buff)
        if dbuf is None:  # Not a valid IPv4 packet
            continue
        if dbuf['prtcl'] != 6:  # TCP protocol
            if surpress:
                continue
            print(f'\n\33[1mRecived \33[35m{utils.prtcls[dbuf["prtcl"]]}\33[39m packet,'
                  ' ignoring...\33[0m (you can use -v to display all IPv4 packets)')
            continue

        data = dbuf['data']
        tcparse = parse.tcp(data)
        utils.print_pac(dbuf, tcparse)

        # Flags: CWR ECE URG ACK PSH RST SYN FIN
        flags = utils.Flags(tcparse["flags"])
        print(flags)

        # ------ Do stuff on the packet ------------
        quad = tcp.Quad(dbuf['srcip'], tcparse['src_port'],
                        dbuf['dstip'], tcparse['dst_port'])
        # Check if connection already exists, if not, create one
        conn_exists = False
        conn = None
        for con in conns:
            print('CON: ', con)
            print('quad: ', con.quad)
            if con.quad == quad:  # The packet is for an existing connection
                conn_exists = True
                conn = con
                break
        if not conn_exists:  # Start a new connection
            conn = tcp.TCB()
            conn.open(quad)
            conns.append(conn)  # Add connection to connections list

        conn.recv(tcparse)


except Exception as e:
    print('\n\33[1mExiting...\33[0m\n', e)
    tun.close()
finally:
    print('\n\33[1mExiting but its good :)\33[0m')
    tun.close()
