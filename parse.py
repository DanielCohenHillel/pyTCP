import sys


def ip(packet: bytes) -> dict:
    if len(packet) < 20:  # Packet can't be smaller than minimum header size
        print('Not a valid IP packet')
        return
    parpack = {
        "ver":    packet[0] >> 4,
        "IHL":    packet[0] & 15,
        "typ":    packet[1],
        "len":    packet[2:4],
        "id":     packet[4:6],
        "fao":    packet[6:8],
        "TTL":    packet[8],
        "prtcl":  packet[9],
        "hcksum": packet[10:12],
        "srcip":  packet[12:16],
        "dstip":  packet[16:20]
    }
    if parpack['ver'] != 4:  # IP version is not 4
        if '-s' in sys.argv:
            return
        print(f'\n\33[1mRecived \33[35mIPv{parpack["ver"]}\33[39m packet,'
              ' ignoring...\33[0m')
        return

    plen = int.from_bytes(parpack['len'], 'big')  # Packet length
    if plen != len(packet):
        print(f"\n\33[1m\33[31mError:\33[0m Packet header said it's \33[1m{plen}\33[0m"
              f" bytes long but it's acutally \33[1m{len(packet)}\33[0m bytes long!"
              "\n\33[1mCorrupted packet.\33[0m")
        return

    ihl = parpack['IHL']  # IP header length
    if ihl < 5:
        print(f"\n\33[1m\33[31mError:\33[0m Header length {ihl*4}b is smaller than the "
              "minimum of 20 bytes.\n\33[1mCorrupted packet.\33[0m")
        return

    # Now that we know header length, we can calc what's the options and what's the data
    parpack['opts'] = packet[20:ihl*4]  # Options go to the end of the header
    parpack['data'] = packet[ihl*4:]  # And the rest is the data
    return parpack


def tcp(packet: bytes) -> dict:
    '''
    Parse TCP packets
    '''
    parpack = {
        'src_port': packet[0:2],
        'dst_port': packet[2:4],
        'seq_num': packet[4:8],
        'ack_num': packet[8:12],
        'dat_off': packet[12] >> 4,
        'rsrvd': packet[12] & 0b1111,
        'flags': packet[13],  # Does not include NS flag!!
        'win_size': packet[14:16],
        'chk_sum': packet[16:18],
        'urg_pnt': packet[18:20]
    }
    # TODO: Check the check sum
    dat_off = parpack['dat_off']*4
    parpack['opts'] = packet[20:dat_off]
    parpack['data'] = packet[dat_off:]
    return parpack
