#!/bin/python

import pytuntap as tt
import parse
import sys
# import tcp
import utils
# from collections.abc import Iterable
res = b'450000541910400040014fc0c0a8012108080808080083ab0010003cd805d15e0000000004d1070000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637'

res = b'0x4500009a293c400001119ef9c0a8007beffffffadc3b076c00863c934d2d534541524348202a20485454502f312e310d0a484f53543a203233392e3235352e3235352e3235303a313930300d0a4d414e3a2022737364703a646973636f766572220d0a4d583a20310d0a53543a2075726e3a6469616c2d6d756c746973637265656e2d6f72673a736572766963653a6469616c3a310d0a0d0a00'
tun = tt.TunTap('Tun', 'tun2')
tun.config('192.168.0.123', '255.255.255.0')
try:
    for _ in range(510000):
        # Command options
        verbose = '-v' in sys.argv
        surpress = '-s' in sys.argv

        buff = tun.read(512)
        dbuf = parse.ip(buff)
        if dbuf is None:  # Not a valid IPv4 packet
            continue
        if not verbose and dbuf['prtcl'] != 6:  # TCP protocol
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


except Exception as e:
    print('\n\33[1mExiting...\33[0m\n', e)
    tun.close()
finally:
    print('\n\33[1mExiting but its good :)\33[0m')
    tun.close()

