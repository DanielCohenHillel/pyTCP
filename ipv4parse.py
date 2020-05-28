def parse(packet) -> dict:
    if len(packet) < 20:  # Packet can't be smaller than minimum header size
        print('Not a valid IP packet')
        return
    if packet[0] >> 4 != 4:  # IP version is not 4
        print(f'\nRecived \33[1mIPv{packet[0]>>4}\33[0m packet, ignoring...')
        return
    parsed = {
        "ver":    packet[0],
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
    return parsed

