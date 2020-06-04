import sys
from typing import NamedTuple


class IPPacket(NamedTuple):
    '''Structure of an IP packet (NamedTuple for easy access)'''
    ver:    int
    IHL:    int
    typ:    int
    len:    bytes
    id:     bytes
    fao:    bytes
    TTL:    int
    prtcl:  int
    hcksum: bytes
    srcip:  bytes
    dstip:  bytes
    opts:   bytes
    data:   bytes


class TCPPacket(NamedTuple):
    '''Structure of a TCP packet (NamedTuple for easy access)'''
    src_port: bytes
    dst_port: bytes
    seq_num:  bytes
    ack_num:  bytes
    dat_off:  int
    rsrvd:    int
    flags:    int
    win_size: bytes
    chk_sum:  bytes
    urg_pnt:  bytes
    opts:     bytes
    data:     bytes


def ip(packet: bytes) -> IPPacket:
    '''Parse IP packet from given bytes of the packet'''
    if len(packet) < 20:  # Packet can't be smaller than minimum header size
        print('Not a valid IP packet')
        return
    ihl = packet[0] & 15
    parpack = IPPacket(
        packet[0] >> 4,    # ver
        ihl,               # IHL
        packet[1],         # typ
        packet[2:4],       # len
        packet[4:6],       # id
        packet[6:8],       # fao
        packet[8],         # TTL
        packet[9],         # prtcl
        packet[10:12],     # hcksum
        packet[12:16],     # srcip
        packet[16:20],     # dstip
        packet[20:ihl*4],  # opts
        packet[ihl*4:]     # data
    )

    if parpack.ver != 4:  # IP version is not 4
        if '-s' in sys.argv:
            return
        print(f'\n\33[1mRecived \33[35mIPv{parpack.ver}\33[39m packet,'
              ' ignoring...\33[0m')
        return

    plen = int.from_bytes(parpack.len, 'big')  # Packet length
    if plen != len(packet):
        print(f"\n\33[1m\33[31mError:\33[0m Packet header said it's \33[1m{plen}\33[0m"
              f" bytes long but it's acutally \33[1m{len(packet)}\33[0m bytes long!"
              "\n\33[1mCorrupted packet.\33[0m")
        return

    if ihl < 5:
        print(f"\n\33[1m\33[31mError:\33[0m Header length {ihl*4}b is smaller than the "
              "minimum of 20 bytes.\n\33[1mCorrupted packet.\33[0m")
        return

    return parpack


def tcp(packet: bytes) -> dict:
    '''Parse TCP packet from given bytes of the packet'''
    if len(packet) < 20:
        print(f"\n\33[1m\33[31mError:\33[0m Packet length {len(packet)}b can't"
              "be smaller than the minimum of 20 bytes.\n\33[1mCorrupted packet.\33[0m")
        return
    dat_off = packet[12] >> 4
    if dat_off < 5:
        print(f"\n\33[1m\33[31mError:\33[0m Header length {dat_off*4}b is smaller"
              " than the minimum of 20 bytes.\n\33[1mCorrupted packet.\33[0m")

    parpack = TCPPacket(
        packet[0:2],           # Source port
        packet[2:4],           # Destenation port
        packet[4:8],           # Sequence number
        packet[8:12],          # Acknewledgement number
        dat_off,               # Data offset
        packet[12] & 0xf,      # Reserved 0's and CWR flag
        packet[13],            # Flags (no CWR)
        packet[14:16],         # Window size
        packet[16:18],         # Checksum
        packet[18:20],         # Urgent pointer
        packet[20:dat_off*4],  # TCP options
        packet[dat_off*4:]     # Actuall data
    )

    # TODO: Check the check sum
    return parpack
