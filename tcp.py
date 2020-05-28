'''
Transmission Control Block (TCB).
The TCP connection object
'''
from enum import Enum
import abc


class State(Enum):
    CLOSED = 0
    LISTEN = 1
    ESTAB = 2
    SYN_RECVD = 3
    SYN_SENT = 4
    CLOSE_WAIT = 5
    LAST_ACK = 6
    FIN_WAIT1 = 7
    FIN_WAIT2 = 8
    CLOSING = 9
    TIME_WAIT = 10


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
    def receive(self):
        pass

    @abc.abstractmethod
    def close(self):
        pass

    @abc.abstractmethod
    def status(self):
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
        pass

    def open(self):
        pass

    def send(self):
        pass

    def receive(self):
        pass

    def close(self):
        pass

    def status(self):
        pass

    def abort(self):
        pass

    def msg_usr(self):
        pass


c = TCB()
