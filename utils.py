
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
    def __init__(self, byte):
        self.cwr = 1 << 7 & byte != 0
        self.ece = 1 << 6 & byte != 0
        self.urg = 1 << 5 & byte != 0
        self.ack = 1 << 4 & byte != 0
        self.psh = 1 << 3 & byte != 0
        self.rst = 1 << 2 & byte != 0
        self.syn = 1 << 1 & byte != 0
        self.fin = 1 << 0 & byte != 0

    def __repr__(self):
        flgstr = f'''\
            \33[1mCWR:\33[0m {self.cwr}
            \33[1mECE:\33[0m {self.ece}
            \33[1mURG:\33[0m {self.urg}
            \33[1mACK:\33[0m {self.ack}
            \33[1mPSH:\33[0m {self.psh}
            \33[1mRST:\33[0m {self.rst}
            \33[1mSYN:\33[0m {self.syn}
            \33[1mFIN:\33[0m {self.fin}
            '''
        return flgstr

