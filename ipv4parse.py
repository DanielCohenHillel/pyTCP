def parse(packet: bytes) -> dict:
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
        "dstip":  packet[16:20],
        "opts":   packet[20:]
    }
    if parpack['ver'] != 4:  # IP version is not 4
        print(f'\nRecived \33[1mIPv{parpack["ver"]}\33[0m packet, ignoring...')
        return

    ihl = int.from_bytes(parpack['len'], 'big')
    if ihl != len(packet):
        print(f"\n\33[1m\33[31mError:\33[0m Packet header said it's \33[1m{ihl}\33[0m bytes long "
              f"but it's acutally \33[1m{len(packet)}\33[0m bytes long!\n\33[1mCurpted packet.")
        return

    return parpack

