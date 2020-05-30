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
    flg_opts = ['ack', 'cwr', 'ece', 'fin', 'psh', 'rst', 'syn', 'urg']

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
        return 1 << cls.flg_opts.index(name)


def mkpkt():
    # -------- layer 3 (IP) --------
    ver = 0x40  # 4 bits - IP version (we use IPv4)
    ihl = 0x05  # 4 bits - Header length - TODO: Calc IHL
    dscp = 0    # 6 bits - differentiated services code point ¯\_(ツ)_/¯
    ecn = 0     # 2 bits - explicit congestion notification ¯\_(ツ)_/¯
    tlen = 20   # 2 bytes - total length
    pid = 0     # 2 bytes - identification
    flags = 0   # 3 bits - flags (evil, DF (don't fragment), MF (more frags))
    frgof = 0   # 13 bits - fragment offset
    ttl = 1     # 1 byte - time to live
    prtcl = 1   # 1 byte - protocol (TCP = 6)
    hchksm = 0  # 2 bytes - header checksum
    srcip = 0   # 4 bytes - source IP
    dstip = 0   # 4 bytes - destenation IP
    iopts = 0   # varied - IPv4 options

    # -------- layer 4 (TCP) --------
    srcp = 0    # 2 bytes - source port
    dstp = 0    # 2 bytes - destenation port
    sqnm = 0    # 4 bytes - sequance number
    acknm = 0   # 4 bytes - acknowledgment number (if ACK flag is set)
    datof = 0   # 4 bit (Data offset) + 3 bit (rsv=0) + 1 bit (NS flag = 0)
    flags = 0   # 1 byte (ack, cwr, ece, fin, psh, rst, syn, urg)
    winsz = 0   # 2 bytes - window size
    chksm = 0   # 2 bytes - check sum
    urgpnt = 0  # 2 bytes - urgent pointer (if URG flag is set)
    topts = 0   # varied (0-40 bytes, multiples of 4) - TCP options
    data = 0    # varied - higher layer data (application layer)

    pktstr = f'{hex(ver | ihl)}{dscp | ecn}'
    print(pktstr)


# octets = [ver | ihl, dscp | ecn, tlen & 0xff00, tlen & 0x00ff,
#           pid & 0xff00, pid & 0x00ff, flags | frgof, ttl, prtcl,
#           hchksm & 0xff00, hchksm & 0x00ff]
# octets.extend(srcip).extend(dstip)

