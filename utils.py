import re
# Table of protocols number
prtcls = []
with open('protocol-numbers-1.csv') as file:
    for row in file:
        spl = row.split(',')
        if isinstance(spl[0], str) and spl[0].isdigit():
            prtcls.append(spl[1])


def print_pac(iph, tcph):
    src_port = int.from_bytes(tcph['src_port'], 'big')
    dst_port = int.from_bytes(tcph['dst_port'], 'big')

    # Print number bytes of data
    print(f'\n\33[1m\33[32m{int.from_bytes(iph["len"], "big")}b of data\33[0m')
    print(f'\33[1mIPv4:\33[0m \33[35m{".".join([str(x) for x in iph["dstip"]])}:{src_port}\33[0m → '
          f'\33[35m{".".join([str(x) for x in iph["srcip"]])}:{dst_port}\33[0m'
          f' \33[1mprotocol:\33[0m {iph["prtcl"]}(\33[35m{prtcls[iph["prtcl"]]}\33[0m) '
          f'\33[1mttl:\33[0m \33[35m{iph["TTL"]}\33[0m')  # print packet info
    print(f'\33[1mData [{len(iph["data"])}b]:'
          f'\33[0m {iph["data"].hex()}')

    print('\33[1m' + '-'*100 + '\33[0m')


class Flags:
    flg_opts = ['cwr', 'ece', 'urg', 'ack', 'psh', 'rst', 'syn', 'fin']

    def __init__(self, byte):
        for i, flag in enumerate(reversed(Flags.flg_opts)):
            self.__setattr__(flag, 1 << i & byte != 0)

    def __repr__(self):
        fstr = '\33[1m[' + ' '.join(self.get_flgs()) + ']\33[0m'
        return fstr

    def get_flgs(self):
        return list(filter(lambda x: x if getattr(self, x) else None, Flags.flg_opts))

    @classmethod
    def flag(cls, name):
        return 1 << 7-cls.flg_opts.index(name)

    def byte(self):
        b = sum([1 << i if getattr(self, flag)
                 else 0 for i, flag in enumerate(reversed(Flags.flg_opts))])
        return b


def mkpkt(data: bytes, srcip: bytearray, dstip: bytearray,
          srcp: bytearray, dstp: bytearray, flags: Flags, acknm=0, iopts=b'', topts=b''):
    # -------- layer 3 (IP) --------
    ver = 0x40  # 4 bits - IP version (we use IPv4)
    ihl = 0x05  # 4 bits - Header length - TODO: Calc IHL
    dscp = 0    # 6 bits - differentiated services code point ¯\_(ツ)_/¯
    ecn = 0     # 2 bits - explicit congestion notification ¯\_(ツ)_/¯
    tlen = 40 + len(data) + len(iopts) + len(topts)   # 2 bytes - total length
    pid = 0     # 2 bytes - identification
    iflg = 0   # 3 bits - flags (evil, DF (don't fragment), MF (more frags))
    frgof = 0   # 13 bits - fragment offset
    ttl = 64     # 1 byte - time to live
    prtcl = 6   # 1 byte - protocol (TCP = 6)
    # srcip = 0   # 4 bytes - source IP
    # dstip = 0   # 4 bytes - destenation IP
    # iopts = 0   # varied - IPv4 options
    iph = bytearray([ver | ihl, dscp | ecn, tlen >> 8, tlen & 0xff,
                     pid & 0xff00, pid & 0x00ff, iflg << 4 | frgof >> 8, frgof & 0xff,
                     ttl, prtcl, 0, 0])
    iph.extend(srcip)
    iph.extend(dstip)
    iph.extend(iopts)
    ipchksm = calc_checksum(iph)
    iph[10:12] = [ipchksm >> 8, ipchksm & 0xff]  # Calc header check sum

    # -------- layer 4 (TCP) --------
    # srcp = 0    # 2 bytes - source port
    # dstp = 0    # 2 bytes - destenation port
    sqnm = 100    # 4 bytes - sequance number
    # acknm = 0   # 4 bytes - acknowledgment number (if ACK flag is set)
    datof = 0x50   # 4 bit (Data offset) + 3 bit (rsv=0) + 1 bit (NS flag = 0)
    tflg = flags.byte()   # 1 byte (ack, cwr, ece, fin, psh, rst, syn, urg)
    winsz = 0xfaf0   # 2 bytes - window size
    # chksm = 0   # 2 bytes - check sum
    urgpnt = 0  # 2 bytes - urgent pointer (if URG flag is set)
    # topts = b''   # varied (0-40 bytes, multiples of 4) - TCP options
    # data = 0    # varied - higher layer data (application layer)

    # TCP header
    tcph = srcp
    tcph.extend(dstp)
    tcph.extend([sqnm >> 24, sqnm >> 16 & 0xff, sqnm >> 8 & 0xff,
                 sqnm & 0xff, acknm >> 24, acknm >> 16 & 0xff,
                 acknm >> 8 & 0xff, acknm & 0xff, datof, tflg,
                 winsz >> 8, winsz & 0xff, 0, 0, urgpnt >> 8, urgpnt >> 8 & 0xff])
    tcph.extend(topts)
    tcph.extend(data)

    # IP psuedo-header
    ipph = srcip
    ipph.extend(dstip)
    ipph.append(0)
    ipph.append(prtcl)
    ipph.extend([tlen >> 8, tlen & 0xff])
    ipph.extend(tcph)

    chksm = calc_checksum(ipph)

    tcph[16:18] = [chksm >> 8, chksm & 0xff]

    # Packet = ip header + tcp heaser\data
    print(len(iph))
    print(len(tcph))
    iph.extend(tcph)
    return iph


def calc_checksum(data: bytes):
    if len(data) % 4 != 0:
        print('\33[1m\33[31mError: \33[0m\33[1m'
              'Header must be a multiple of 32 bits...\33[0m')
    # list of all 2-byte (4 hex-digits) words in the packet (in hex)
    words = re.findall('.'*4, data.hex())
    # Turning hex into ints and summing
    s = sum([int(word, 16) for word in words])
    # check carry (if more than 4 hex digits, carry)
    while len(hex(s)) > 6:
        s = int(hex(s)[-4:], 16) + int(hex(s)[-5], 16)
    return s

# octets = [ver | ihl, dscp | ecn, tlen & 0xff00, tlen & 0x00ff,
#           pid & 0xff00, pid & 0x00ff, flags | frgof, ttl, prtcl,
#           hchksm & 0xff00, hchksm & 0x00ff]
# octets.extend(srcip).extend(dstip)


# data = b''
# srcip = bytearray([192, 168, 0, 123])
# dstip = bytearray([192, 168, 0, 68])

# srcp = bytearray([0, 80])
# dstp = bytearray([0, 100])

# flags = Flags(2)
# print('\33[1m----------------------------------------\33[0m\n')
# pkt = mkpkt(data, srcip, dstip, srcp, dstp, flags)
# print(pkt.hex())
