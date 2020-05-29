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
    SYN_RCVD = 4
    SYN_SENT = 5
    CLOSE_WAIT = 6
    LAST_ACK = 7
    FIN_WAIT1 = 8
    FIN_WAIT2 = 9
    CLOSING = 10
    TIME_WAIT = 11


class Quad:
    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.src = (src_ip, src_port)
        self.dst = (dst_ip, dst_port)


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
    def __init__(self, quad):
        self.state = State.LISTEN
        self.quad = quad

    def open(self):
        '''
        CLOSED -> LISTEN
        CLOSED -> SYN_SENT
        '''
        pass

    def send(self):
        '''
        CLOSED -----> SYN_SENT
        LISTEN -----> SYN_SENT
        LISTEN -----> SYN_RCVD
        SYN_SENT ---> SYN_RCVD
        SYN_SENT ---> ESTAB
        SYN_RCVD ---> FIN_WAIT1
        ESTAB ------> CLOSE_WAIT
        ESTAB ------> FIN_WAIT1
        CLOSE_WAIT -> LAST_ACK
        FIN_WAIT1 --> CLOSING
        FIN_WAIT2 --> TIME_WAIT
        '''
        pass

    def recv(self):  #
        '''
        LISTEN ----> SYN_RCVD
        SYN_RCVD --> ESTAB
        ESTAB -----> CLOSE_WAIT
        FIN_WAIT1 -> FIN_WAIT2
        FIN_WAIT1 -> CLOSING
        FIN_WAIT2 -> TIME_WAIT
        CLOSING ---> TIME_WAIT
        LAST_ACK --> CLOSED
        '''
        pass

    def close(self):
        '''
        LISTEN -----> CLOSED
        SYN_SENT ---> CLOSED
        SYN_RCVD ---> FIN_WAIT1
        ESTAB ------> FIN_WAIT1
        CLOSE_WAIT -> LAST_ACK
        '''
        pass

    def stat(self):
        pass

    def abort(self):
        pass

    def msg_usr(self):
        pass


# c = TCB()
