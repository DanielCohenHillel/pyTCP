import pytuntap as tt
import ipv4parse as ip4p
import sys
import tcp
import utils
# from collections.abc import Iterable


tun = tt.TunTap('Tun', 'tun2')
tun.config('192.168.0.123', '255.255.255.0')
try:
    for _ in range(500):
        verbose = '-v' in sys.argv
        surpress = '-s' in sys.argv

        buff = tun.read(512)
        dbuf = ip4p.parse(buff)
        if dbuf is None:  # Not a valid IPv4 packet
            continue
        if not verbose and dbuf['prtcl'] != 6:  # TCP protocol
            if surpress:
                continue
            print(f'\n\33[1mRecived \33[35m{utils.prtcls[dbuf["prtcl"]]}\33[39m packet,'
                  ' ignoring...\33[0m (you can use -v to display all IPv4 packets)')
            continue

        data = dbuf['data']
        tcp_dat = tcp.parse(data)
        utils.print_pac(dbuf, tcp_dat)


except Exception as e:
    print('\nExiting...\n', e)
    tun.close()
finally:
    print('\nExiting but its good :)')
    tun.close()

