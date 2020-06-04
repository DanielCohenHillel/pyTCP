'''
Transmission Control Block (TCB).
The TCP connection object
'''
from enum import Enum
import abc
import logging
import utils
from typing import NamedTuple


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


class Node(NamedTuple):
    ip:   bytes
    port: bytes


class Quad:
    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.src = Node(src_ip, src_port)
        self.dst = Node(dst_ip, dst_port)

    def __eq__(self, other):
        return self.src == other.src and self.dst == other.dst

    def __repr__(self):
        qstr = f'''
            \33[1mSource:
                \33[1mIP:\33[0m   {'.'.join([str(b) for b in self.src.ip])}
                \33[1mPort:\33[0m {int.from_bytes(self.src.port, 'big')}
            \33[1mDestenation:\33[0m
                \33[1mIP:\33[0m   {'.'.join([str(b) for b in self.dst.ip])}
                \33[1mPort:\33[0m {int.from_bytes(self.dst.port, 'big')}
            '''
        return qstr


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
    def __init__(self, tun):
        self.state = State.LISTEN
        self.quad = None
        self.tun = tun  # TODO: change this, should combine tcpimp.py with tcp.py
        self.sqnm = 0
        self.acknm = 0

    def open(self, quad):
        '''
        CLOSED -> LISTEN <---------------------- *
        CLOSED -> SYN_SENT
        '''
        if self.state == State.CLOSED:
            self.quad = quad
        if self.state == State.LISTEN:
            self.quad = quad
        else:
            print("\33[31m\33[1mError:\33[0m\33[1m connection already exists.")

    def send(self, packet):
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
        self.tun.write(packet)

    def recv(self, packet):
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
        data = packet.data
        self.acknm += len(data)

        # Print the sent data in ASCII
        if len(data) != 0:
            print("\33[1mThe internet said:\33[33m ",
                  "".join([chr(d) for d in data]) + '\33[0m')
        # print('\33[1m~~ RECV ~~\33[1m')
        if self.state == State.CLOSED:
            print("\33[31m\33[1mError:\33[0m\33[1m connection doesn't exist.")
            return
        # if self.state in [State.LISTEN, State.SYN_SENT, State.SYN_RCVD]:
        #     pass  # TODO: Queue for processing. (read from tun device)
        # if self.state in [State.ESTAB, State.FIN_WAIT1, State.FIN_WAIT2]:
        #     pass  # TODO: Queue for processing.

        if self.state == State.LISTEN:
            if packet.flags == utils.Flags.flag('syn'):
                # Send SYN,ACK
                self.state = State.SYN_RCVD
                self.acknm = int.from_bytes(packet.seq_num, 'big') + 1
                # SYN, ACK (TODO: make simpler to do)
                flags = utils.Flags(0x12)
                snd = self.mkpkt(flags=flags)
                self.send(snd)
                self.sqnm += 1
                # self.send(snd)
            return

        if self.state == State.SYN_RCVD:
            if packet.flags == utils.Flags.flag('ack'):
                self.state = State.ESTAB
                print(f'\n\33[1m\33[32mCnnection Established!!\33[0m')
            return

        if self.state == State.ESTAB:
            flags = utils.Flags('ack')  # ACK
            print('flag=', flags)

            snd = self.mkpkt(flags=flags)
            if packet.flags & utils.Flags.flag('fin'):
                print(f'\n\33[1m\33[31mClosing connection!!\33[0m')
                self.state = State.CLOSE_WAIT
                self.close()
            self.send(snd)

    def close(self):
        '''
        LISTEN -----> CLOSED
        SYN_SENT ---> CLOSED
        SYN_RCVD ---> FIN_WAIT1
        ESTAB ------> FIN_WAIT1
        CLOSE_WAIT -> LAST_ACK
        '''
        if self.state == State.CLOSE_WAIT:
            self.state = State.LAST_ACK
            snd = self.mkpkt(flags='fin')
            self.send(snd)
            # TODO: wait for ack of fin and remove from connections list
            return

        if self.state == State.ESTAB:
            self.state = State.FIN_WAIT1
            snd = self.mkpkt(flags='fin')
            self.send(snd)

    def status(self):
        return self.state

    def abort(self):
        pass

    def msg_usr(self):
        pass

    def mkpkt(self, data=b'', flags=0):
        '''Wrapper for utils.mkkpkt to automatically use objects properties'''
        if isinstance(flags, int) or isinstance(flags, str):
            flags = utils.Flags(flags)
        print('flaaaaag   =    ', flags)
        return utils.mkpkt(data, self.quad, flags, self.acknm, self.sqnm)

