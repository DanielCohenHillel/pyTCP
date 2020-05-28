import struct

import subprocess
import sys
import threading
import logging
import os
import math

import fcntl


class Packet(object):
    '''
    data layer3 data
    frame layer2 data 
    '''

    def __init__(self, data=None, frame=None):
        self.data = None
        if frame:
            self.load(frame)
            return

        if len(data) > 20:
            self.data = data

    def load(self, frame):
        if len(frame) > 34:
            self.data = frame[12+2:]

    def get_version(self):
        return self.data[0] >> 4 if self.data else 0

    def get_src(self):
        return self.data[12:16] if self.data else None

    def get_dst(self):
        return self.data[16:20] if self.data else None

    def get_payload(self):
        return self.data[(self.data[0] & 0x0f) << 2:] if self.data else None

    def get_protocol(self):
        return self.data[9] if self.data else 0

    def wrap(self, payload, protocol, dst_ip, src_ip):
        return None


def TunTap(nic_type, nic_name=None):
    '''
    TunTap to init a device , after init, you should
    input:
        nic_type:  must be "Tun" or "Tap"
        nic_name:  device name, default is None,
                    on Linux system if None will auto generate,can be obtained by tap.name
                    else will reuse the name of given
    return :
        Tap
    after tap create, can be config(ip,mask),then canbe read or write ,please refer
    '''
    tap = Tap(nic_type, nic_name)
    tap.create()
    return tap


class Tap(object):
    '''
    Linux Tap
    please use TunTap(nic_type,nic_name) ,it will invoke this class if on linux
    '''

    def __init__(self, nic_type, nic_name=None):
        self.nic_type = nic_type
        self.name = nic_name
        self.mac = b"\x00"*6
        self.handle = None
        self.ip = None
        self.mask = None
        self.gateway = None
        self.read_lock = threading.Lock()
        self.write_lock = threading.Lock()

    def create(self):
        TUNSETIFF = 0x400454ca
        TUNSETOWNER = 0x400454cc
        TUNSETGROUP = 0x400454ce
        TUNSETPERSIST = 0x400454cb
        IFF_TUN = 0x0001
        IFF_TAP = 0x0003
        # IFF_MULTI_QUEUE = 0x0100
        IFF_NO_PI = 0x1000
        O_RDWR = 0x2
        # Open TUN device file.
        tun = os.open('/dev/net/tun', O_RDWR)
        if not tun:
            return None
        # Tall it we want a TUN device named tun0.
        if self.nic_type == "Tap":
            flags = IFF_TAP | IFF_NO_PI
        if self.nic_type == "Tun":
            flags = IFF_TUN | IFF_NO_PI
        if self.name:
            ifr_name = self.name.encode() + b'\x00'*(16-len(self.name.encode()))
        else:
            ifr_name = b'\x00'*16
        ifr = struct.pack('16sH22s', ifr_name, flags, b'\x00'*22)
        # print(ifr)
        ret = fcntl.ioctl(tun, TUNSETIFF, ifr)
        # print(ret,len(ret),ifr)
        logging.debug("%s %s" % (ifr, ret))
        dev, _ = struct.unpack('16sH', ret[:18])
        dev = dev.decode().strip("\x00")
        self.name = dev

        # Optionally, we want it be accessed by the normal user.
        fcntl.ioctl(tun, TUNSETOWNER, struct.pack("H", 1000))
        fcntl.ioctl(tun, TUNSETGROUP, struct.pack("H", 1000))
        fcntl.ioctl(tun, TUNSETPERSIST, struct.pack("B", True))
        self.handle = tun

        if self.handle:
            return self
        else:
            return None

    def _get_maskbits(self, mask):
        masks = mask.split(".")
        maskbits = 0
        if len(masks) == 4:
            for i in range(4):
                nbit = math.log(256-int(masks[i]), 2)
                if nbit == int(nbit):
                    maskbits += 8-nbit
                else:
                    return
        return int(maskbits)

    def config(self, ip, mask, gateway="0.0.0.0"):
        '''
        config device's ip and mask
        input:
            ip:  ipaddress string, such as "192.168.1.5"
            mask: netmask string, such as "255.255.255.0"
            gateway: it is not used in this version
        return :
            None  if failure
            self  if success
        after tap configed,then canbe read or write ,please refer
        '''
        self.ip = ip
        self.mask = mask
        self.gateway = gateway
        nmask = self._get_maskbits(self.mask)
        try:
            subprocess.check_call('ip link set '+self.name+' up', shell=True)
            subprocess.check_call('ip addr add '+self.ip+'/%d ' %
                                  nmask + " dev " + self.name, shell=True)
        except:
            logging.warning("error when config")
            self.close()
            return None
        return self

    def close(self):
        '''
        close device
        input:
            None
        return :
            None
        '''
        os.close(self.handle)
        try:
            mode_name = 'tun' if self.nic_type == "Tun" else 'tap'
            # print('ip tuntap delete mode '+ mode_name + " "+ self.name)
            subprocess.check_call('ip addr delete '+self.ip+'/%d ' %
                                  self._get_maskbits(self.mask) + " dev " + self.name, shell=True)
            subprocess.check_call('ip tuntap delete mode '
                                  + mode_name + " " + self.name, shell=True)

        except Exception as e:
            logging.debug(e)

    def read(self, size=1522):
        '''
        read device data with given size
        input:
            size:  read max size , int . such as size = 1500
        return :
            bytes:
        '''
        self.read_lock.acquire()
        data = os.read(self.handle, size)
        self.read_lock.release()
        return data

    def write(self, data):
        '''
        write data to device
        input:
            data:  byte[] . such as data = b'\x00'*100
        return :
            int:  writed bytes
        '''
        self.write_lock.acquire()
        try:
            result = os.write(self.handle, data)
        except:
            result = 0
        self.write_lock.release()
        return result
