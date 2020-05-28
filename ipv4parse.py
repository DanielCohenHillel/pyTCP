def parse(packet) -> dict:
    if len(packet) < 20:
        print('Not a valid IPv4 packet')
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

