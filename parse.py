import sys
from typing import NamedTuple


class IPPacket(NamedTuple):
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


def ip(packet: bytes) -> dict:
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
    '''
    Parse TCP packets
    '''
    dat_off = packet[12] >> 4
    parpack = TCPPacket(
        packet[0:2],
        packet[2:4],
        packet[4:8],
        packet[8:12],
        dat_off,
        packet[12] & 0b1111,
        packet[13],  # Does not include NS flag!!
        packet[14:16],
        packet[16:18],
        packet[18:20],
        packet[20:dat_off*4],
        packet[dat_off*4:]
    )
    # parpack = {
    #     'src_port': packet[0:2],
    #     'dst_port': packet[2:4],
    #     'seq_num': packet[4:8],
    #     'ack_num': packet[8:12],
    #     'dat_off': packet[12] >> 4,
    #     'rsrvd': packet[12] & 0b1111,
    #     'flags': packet[13],  # Does not include NS flag!!
    #     'win_size': packet[14:16],
    #     'chk_sum': packet[16:18],
    #     'urg_pnt': packet[18:20]
    # }

    # TODO: Check the check sum
    # parpack['opts'] = packet[20:dat_off]
    # parpack['data'] = packet[dat_off:]
    return parpack
