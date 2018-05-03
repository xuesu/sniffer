"""
@author xuesu
"""
# -*- coding: utf-8 -*-

import ctypes
import threading

import functions.winpcapy_types as wtypes
import loggers
import packet
from exceptions import *

HANDLER_SIGNATURE = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_ubyte),
                                     ctypes.POINTER(wtypes.pcap_pkthdr),
                                     ctypes.POINTER(ctypes.c_ubyte))
BUFFSZ = 512

logger = loggers.new_logger("winpcapy", "DEBUG")


class WinPCapThreadManager:
    def __init__(self, *args, **kwargs):
        self.phandle = None
        self.lock = threading.Lock()
        self.should_stop = False
        self.callback = None
        self.device_name = ""
        self.allowed_protocos = set()
        self.filter_str = ""
        self.num = 0
        self.thread = None
        self.should_rest = False

    def run(self):
        while not self.should_stop:
            while self.should_rest:
                pass
            self.lock.acquire()
            try:
                if self.should_stop:
                    break
                if self.phandle is None:
                    if not self.device_name:
                        raise ThreadUnInitializedError()
                    self.phandle = WinPCap.open_device(self.device_name)
                next_packet = WinPCap.pcap_read_nxt(self.phandle)
                if next_packet is not None:
                    next_packet = packet.Packet.unpack(next_packet)
                    next_packet.num = self.num
                    self.num += 1
                    if next_packet.final_protocol in self.allowed_protocos:
                        self.callback(next_packet)
            except NotImplementedError:
                pass
            finally:
                self.lock.release()

    def start(self):
        if self.thread is None or not self.thread.is_alive():
            self.should_stop = False
            self.thread = threading.Thread(target=self.run)
            self.thread.start()

    def stop(self):
        if self.thread is not None:
            self.should_stop = True
            self.thread.stop()


class WinPCap:
    def __init__(self):
        self.device_infos = None
        self.lock = threading.Lock()
        self.threads = dict()

    def __enter__(self):
        if self.device_infos is None:
            self.device_infos = WinPCap.list_all_devices()

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.device_infos is not None:
            wtypes.pcap_freealldevs()

    @staticmethod
    def list_all_devices():
        err_buff = ctypes.c_buffer(BUFFSZ)
        ppcap = ctypes.pointer(wtypes.pcap_if_t())
        if wtypes.pcap_findalldevs(ctypes.byref(ppcap), err_buff) < 0:
            raise UnableListAllDevicesError(err_buff)
        alldevs = dict()
        while bool(ppcap):
            alldevs[str(ppcap.contents.name, encoding='utf8')] = str(ppcap.contents.description, encoding='utf8')
            ppcap = ppcap.contents.next
        return alldevs

    @staticmethod
    def open_device(device_name):
        err_buff = ctypes.c_buffer(BUFFSZ)
        device_name_cstr = ctypes.c_buffer(init=bytes(device_name, encoding='ascii'))
        ppcap = wtypes.pcap_open_live(device_name_cstr, 65535, 1, 5000, err_buff)
        if not bool(ppcap):
            raise UnableOpenDeviceError(device_name, ctypes.string_at(err_buff))
        return ppcap.contents

    @staticmethod
    def close_device(phandle):
        if phandle is not None:
            try:
                wtypes.pcap_close(phandle)
            except Exception:
                # unsafe
                pass

    @staticmethod
    def pcap_compile(phandle, filter_str, netmask=0xffffff):
        if not isinstance(filter_str, bytes):
            filter_str = bytes(filter_str, encoding="ascii")
        fcode = wtypes.bpf_program()
        filter_cstr = ctypes.create_string_buffer(filter_str)
        # netmask = ctypes.c_uint32(netmask)
        if wtypes.pcap_compile(phandle, ctypes.byref(fcode), filter_cstr, 1, netmask) < 0:
            raise UnableSetFilterError(filter_str, "pcap_compile")
        return fcode

    @staticmethod
    def pcap_set_filter(phandle, filter_str, netmask=0xffffff):
        if not filter_str:
            return
        fcode = WinPCap.pcap_compile(phandle, filter_str, netmask)
        if wtypes.pcap_setfilter(phandle, fcode) < 0:
            raise UnableSetFilterError(filter_str, "pcap_set_filter")

    @staticmethod
    def pcap_read_nxt(phandle):
        pheader = ctypes.POINTER(wtypes.pcap_pkthdr)()
        pkt_data = ctypes.POINTER(wtypes.u_char)()
        fl = wtypes.pcap_next_ex(phandle, ctypes.byref(pheader), ctypes.byref(pkt_data))
        if fl == 0:
            return None
        if fl < 1:
            raise ReadError()
        res = ctypes.string_at(pkt_data, pheader.contents.len)
        return res

    def run_t(self, sid, callback):
        if sid not in self.threads:
            raise ThreadUnInitializedError()
        self.threads[sid].should_rest = True
        self.threads[sid].lock.acquire()
        self.threads[sid].callback = callback
        self.threads[sid].should_stop = False
        self.threads[sid].should_rest = False
        self.threads[sid].lock.release()
        self.threads[sid].start()

    def stop_t(self, sid):
        if sid not in self.threads:
            raise ThreadUnInitializedError()
        self.threads[sid].should_rest = True
        self.threads[sid].lock.acquire()
        self.threads[sid].should_stop = True
        self.threads[sid].should_rest = False
        self.threads[sid].lock.release()

    def set_protos_t(self, sid, protos):
        if sid not in self.threads:
            raise ThreadUnInitializedError()
        protos = set([packet.Packet.PROTOCOL[proto.upper()] for proto in protos])
        filter_str = ' and '.join(set([proto.get_filter_str() for proto in protos]))
        self.threads[sid].should_rest = True
        self.threads[sid].lock.acquire()
        try:
            WinPCap.pcap_set_filter(self.threads[sid].phandle, filter_str)
            self.threads[sid].filter_str = filter_str
            self.threads[sid].allowed_protocos = set.union(*[proto.get_sub_protocol() for proto in protos])
        finally:
            self.threads[sid].should_rest = False
            self.threads[sid].lock.release()

    def set_device_t(self, sid, device_name):
        self.lock.acquire()
        if sid not in self.threads:
            self.threads[sid] = WinPCapThreadManager()
        self.lock.release()
        self.threads[sid].should_rest = True
        self.threads[sid].lock.acquire()
        try:
            WinPCap.close_device(self.threads[sid].phandle)
            self.threads[sid].phandle = WinPCap.open_device(device_name)
            self.threads[sid].device_name = device_name
        finally:
            self.threads[sid].should_rest = False
            self.threads[sid].lock.release()

    def remove_t(self, sid):
        self.lock.acquire()
        try:
            if sid in self.threads:
                self.threads[sid].should_rest = True
                self.threads[sid].lock.acquire()
                self.threads[sid].should_rest = False
                self.threads[sid].should_stop = True
                self.threads[sid].lock.release()
                self.threads[sid].stop()
                self.threads.pop(sid)
        finally:
            self.lock.release()

    def get_device_name_now(self, sid):
        if sid in self.threads:
            return self.threads[sid].device_name
        return None

    def get_filter_str_now(self, sid):
        if sid in self.threads:
            return self.threads[sid].filter_str
        return None
