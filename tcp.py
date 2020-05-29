'''
Transmission Control Block (TCB).
The TCP connection object
'''
from enum import Enum
import abc
import logging


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
        self.state = State.CLOSED

    def open(self, quad):
        '''
        CLOSED -> LISTEN <---------------------- *
        CLOSED -> SYN_SENT
        '''
        if self.state == State.CLOSED:
            pass
        if self.state == State.LISTEN:
            pass
        print("\33[31m\33[1mError:\33[0m\33[1m connection already exists.")

    def send(self):
        '''
        CLOSED -----> SYN_SENT
        LISTEN -----> SYN_SENT <--------------- *
        LISTEN -----> SYN_RCVD <--------------- *
        SYN_SENT ---> SYN_RCVD
        SYN_SENT ---> ESTAB <------------------ *
        SYN_RCVD ---> FIN_WAIT1
        ESTAB ------> CLOSE_WAIT
        ESTAB ------> FIN_WAIT1
        CLOSE_WAIT -> LAST_ACK
        FIN_WAIT1 --> CLOSING
        FIN_WAIT2 --> TIME_WAIT
        '''
        pass

    def recv(self):
        '''
        LISTEN ----> SYN_RCVD <---------------- *
        SYN_SENT --> ESTAB <------------------- *
        SYN_RCVD --> ESTAB <------------------- *
        SYN_SENT --> SYN_RCVD
        ESTAB -----> CLOSE_WAIT
        FIN_WAIT1 -> FIN_WAIT2
        FIN_WAIT1 -> CLOSING
        FIN_WAIT2 -> TIME_WAIT
        CLOSING ---> TIME_WAIT
        LAST_ACK --> CLOSED
        '''
        if self.state == State.CLOSED:
            logging.log(40,
                        "\33[31m\33[1mError:\33[0m connection doesn't exist.")
        if self.state in [State.LISTEN, State.SYN_SENT, State.SYN_RCVD]:
            pass  # TODO: Queue for processing. (read from tun device)
        if self.state in [State.ESTAB, State.FIN_WAIT1, State.FIN_WAIT2]:
            pass  # TODO: Queue for processing.

    def close(self):
        '''
        LISTEN -----> CLOSED
        SYN_SENT ---> CLOSED
        SYN_RCVD ---> FIN_WAIT1
        ESTAB ------> FIN_WAIT1
        CLOSE_WAIT -> LAST_ACK
        '''
        pass

    def status(self):
        return self.state

    def abort(self):
        pass

    def msg_usr(self):
        pass


c = TCB()
c.open(1)
