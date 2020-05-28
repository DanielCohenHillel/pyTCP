# import tuntap as tt

# tun = tt.TunTap('Tun', 'tun2')
# # tun.create()
# tun.config('192.168.1.123', '255.255.255.0')
# try:
#     for _ in range(100):
#         buff = tun.read(512)
#         print(f'\33[1m{len(buff)}\33[0m -> {buff}')
# except Exception as e:
#     print('Exiting...\n', e)
#     tun.close()
# finally:
#     print('Exiting but its good :)')

tun = tt.TunTap('Tun', 'tun2')
tun.config('192.168.0.123', '255.255.255.0')
try:
    for _ in range(100):
        buff = tun.read(512)
        buff_arr = [int(i) for i in buff]
        # print(f'\n\33[1m{len(buff)}\33[0m -> {val_arr}')
        print(f'\n\33[1m{len(buff)}b\33[0m of data')
        try:
            dbuf = {
                "ver":    buff_arr[0],
                "type":   buff_arr[1],
                "length": buff_arr[2:5],
                "id":     buff_arr[5:7],
                "fao":    buff_arr[7:9],
                "ttl":    buff_arr[9],
                "prtcl":  buff_arr[10],
                "hcheck": buff_arr[11:13],
                "srcip":  buff_arr[13:17],
                "dstip":  buff_arr[17:21],
                "ICMP":   buff_arr[21:]
            }
            for key, value in dbuf.items():
                print(f'\33[1m{key}:\33[0m {value}')
        except:
            print('not ICMP')

except Exception as e:
    print('Exiting...\n', e)
    tun.close()
finally:
    print('Exiting but its good :)')
    tun.close()   tun.close()
