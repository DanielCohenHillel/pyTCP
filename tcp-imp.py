import pytuntap as tt
import ipv4parse as ip4p
from collections.abc import Iterable

# Table of protocols number
prtcls = []
with open('protocol-numbers-1.csv') as file:
    for row in file:
        spl = row.split(',')
        if isinstance(spl[0], str) and spl[0].isdigit():
            prtcls.append(spl[1])

tun = tt.TunTap('Tun', 'tun2')
tun.config('192.168.0.123', '255.255.255.0')
try:
    for _ in range(100):
        # print(f'\n\33[1m{len(buff)}\33[0m -> {val_arr}')
        buff = tun.read(512)
        dbuf = ip4p.parse(buff)
        if dbuf is None:  # Not a valid IPv4 packet
            continue

        # Print number bytes of data
        print(f'\n\33[1m\33[32m{len(buff)}b of data\33[0m')
        print(f'\33[1mIPv4:\33[0m \33[35m{".".join([str(x) for x in dbuf["dstip"]])}\33[0m → '
              f'\33[35m{".".join([str(x) for x in dbuf["srcip"]])}\33[0m'
              f' \33[1mprotocol:\33[0m {dbuf["prtcl"]}(\33[35m{prtcls[dbuf["prtcl"]]}\33[0m) '
              f'\33[1mttl:\33[0m \33[35m{dbuf["TTL"]}\33[0m')  # print packet info
        print(f'\33[1mData [{len(dbuf["data"])}b] (Handled by a higher level protocol):'
              f'\33[0m {dbuf["data"].hex()}')


except Exception as e:
    print('\nExiting...\n', e)
    tun.close()
finally:
    print('\nExiting but its good :)')
    tun.close()
