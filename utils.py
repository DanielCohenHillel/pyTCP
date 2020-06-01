import re
import struct
import array

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


def mkpkt(data: bytes, quad, flags: Flags, acknm=0, iopts=b'', topts=b''):
    '''Create a TCP/IP packet from specified parameters'''
    # Quad object to adresses
    srcip = bytes(quad.dst[0])
    dstip = bytes(quad.src[0])

    srcp = bytes(quad.dst[1])
    dstp = bytes(quad.src[1])
    # -------- layer 3 (IP) --------
    ver = 0x40  # 4 bits - IP version (we use IPv4)
    ihl = 0x05  # 4 bits - Header length - TODO: Calc IHL
    dscp = 0    # 6 bits - differentiated services code point ¯\_(ツ)_/¯
    ecn = 0     # 2 bits - explicit congestion notification ¯\_(ツ)_/¯
    tlen = 40 + len(data) + len(iopts) + len(topts)   # 2 bytes - total length
    pid = 0     # 2 bytes - identification
    iflg = 0    # 3 bits - flags (evil, DF (don't fragment), MF (more frags))
    frgof = 0   # 13 bits - fragment offset
    ttl = 64    # 1 byte - time to live
    prtcl = 6   # 1 byte - protocol (TCP = 6)

    iph = struct.pack(
        "!BBHHBBBBH4s4s",  # Format (H=2bytes  I=4bytes  B=1Byte, s=bytestring)
        ver | ihl,         # IP version | IP header length
        dscp | ecn,        #
        tlen,              # Total length of the packet
        pid,               # Identification
        iflg << 4 | frgof >> 8,  # IP flags | fragment offset
        frgof & 0xff,      # Fragment offset
        ttl,               # Time To Live
        prtcl,             # Protocol number (TCP = 6)
        0,                 # Checksum (to be calculated later)
        srcip,             # Source IP address
        dstip              # Destenation IP address
    )
    ipchksm = calc_checksum(iph)
    iph = iph[:10] + struct.pack('H', ipchksm) + iph[12:]

    # -------- layer 4 (TCP) --------
    sqnm = 100           # 4 bytes - sequance number
    datof = 0x50         # 4 bit (Data offset) + 3b (rsv=0) + 1b (NS flag = 0)
    tflg = flags.byte()  # 1 byte (ack, cwr, ece, fin, psh, rst, syn, urg)
    winsz = 0xfaf0       # 2 bytes - window size
    urgpnt = 0           # 2 bytes - urgent pointer (if URG flag is set)

    # TCP header
    tcph = struct.pack(
        '!2s2sIIBBHHH',  # format (H=2bytes  I=4bytes  B=1Byte, s=bytestring)
        srcp,            # Source port
        dstp,            # Destenation port
        sqnm,            # Sequence number
        acknm,           # Acknewledgement nubmer
        datof,           # Data offset (first 4bit) rsrvd (3bit) cwr flg (1bit)
        tflg,            # Flags (TCP)
        winsz,           # Window Size
        0,               # Checksum (initialy 0)
        urgpnt           # Urgent pointer
    )

    # IP psuedo-header (for checksum calculation)
    tcplen = len(tcph) + len(topts) + len(data)
    ipph = struct.pack(
        '!4s4sHH',  # Format
        srcip,      # Source Address
        dstip,      # Destination Address
        prtcl,      # Protocol ID
        tcplen      # TCP Length
    )

    chksm = calc_checksum(ipph + tcph + data)
    del ipph  # Discard of psuedo-header, only use to calc the checksum

    # Insert the checksum, was privously 0 for calculation purpouses
    tcph = tcph[:16] + struct.pack('H', chksm) + tcph[18:]

    # Packet = ip header (iph) + tcp heaser (tcph) + data
    return iph + tcph + data


def calc_checksum(data: bytes):
    # Check that the data is of valid length
    if len(data) % 2 != 0:
        data += b'\0'
    # Sum all words
    res = sum(array.array("H", data))
    # Carry
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16
    # Return one's complement
    return (~res) & 0xffff
