import tuntap as tt
import ipv4parse as ip4p

tun = tt.TunTap('Tun', 'tun2')
tun.config('192.168.0.123', '255.255.255.0')
try:
    for _ in range(100):
        buff = tun.read(512)
        buff_arr = [int(i) for i in buff]
        # print(f'\n\33[1m{len(buff)}\33[0m -> {val_arr}')
        print(f'\n\33[1m{len(buff)}b\33[0m of data')
        try:
            dbuf = ip4p.parse(buff)
            for key, value in dbuf.items():
                print(f'\33[1m{key}:\33[0m {value}')
        except Exception as e:
            print('Not IPv4', e)

except Exception as e:
    print('Exiting...\n', e)
    tun.close()
finally:
    print('Exiting but its good :)')
    tun.close()
