'''
Transmission Control Block (TCB).
The TCP connection object
'''
from enum import Enum
import abc


class State(Enum):
    CLOSED = 1
    LISTEN = 2
    ESTAB = 3
    SYN_RECVD = 4
    SYN_SENT = 5
    CLOSE_WAIT = 6
    LAST_ACK = 7
    FIN_WAIT1 = 8
    FIN_WAIT2 = 9
    CLOSING = 10
    TIME_WAIT = 11


class quad:
    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.src = (src_ip, src_port)
        self.dst = (dst_ip, dst_port)


def parse(packet):
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
    dat_off = parpack['dat_off']*4
    parpack['opts'] = packet[20:dat_off]
    parpack['data'] = packet[dat_off:]
    return parpack


class TCBase(abc.ABC):
    @abc.abstractmethod
    def __init__(self):
        pass

    # ---------------- User ------------------
    @abc.abstractmethod
    def open(self):
        pass

    @abc.abstractmethod
    def send(self):
        pass

    @abc.abstractmethod
    def recv(self):
        pass

    @abc.abstractmethod
    def close(self):
        pass

    @abc.abstractmethod
    def stat(self):
        pass

    @abc.abstractmethod
    def abort(self):
        pass

    @abc.abstractmethod
    def msg_usr(self):
        pass

    # ------------------------ Lower level ---------------------
    # !!! TO BE ADDED IN THE FUTUTE IF I EVER GET TO IT MAYBE !!!


class TCB(TCBase):
    def __init__(self):
        self.state = State.CLOSED

    def open(self):
        pass

    def send(self):
        pass

    def recv(self):
        pass

    def close(self):
        pass

    def stat(self):
        pass

    def abort(self):
        pass

    def msg_usr(self):
        pass


# c = TCB()
