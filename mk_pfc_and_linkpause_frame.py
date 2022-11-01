# -*- coding:utf8 -*- 
import struct as s
import binascii
from scapy.all import wrpcap, Ether

class pfc_frame():
    SMAC = '00:1b:21:a5:86:d8'
    DMAC = '01:80:C2:00:00:01'
    Ethertype = 0x8808
    MAC_control_Opcode = 0x0101
    PADDING_25th = 0x00
    class_enable_vector = 0x00
    PAUSE_TIME = [0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000]
    
    def __init__(self, prio, pause_time):
        self.PAUSE_TIME[prio] = pause_time
        self.class_enable_vector = self.class_enable_vector | (1<<prio)
    
    def set_pause_prio(self, prio, pause_time):
        self.PAUSE_TIME[prio] = pause_time
        self.class_enable_vector = self.class_enable_vector | (1<<prio)

    def unset_pause_prio(self, prio):
        self.PAUSE_TIME[prio] = 0
        self.class_enable_vector = self.class_enable_vector | (0xff^(1<<prio))

    def unset_pause_all(self):
        self.PAUSE_TIME = [0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000]
        self.class_enable_vector = 0x00

    def makepacket(self):
        MC_Opcode = s.pack('!H', self.MAC_control_Opcode)     # 16 bit
        PD = s.pack('!B', self.PADDING_25th)                  # 8 bit
        CE_Vector = s.pack('!B', self.class_enable_vector)    # 8 bit
        P_Time_0 = s.pack('!H', self.PAUSE_TIME[0])           # 16 bit
        P_Time_1 = s.pack('!H', self.PAUSE_TIME[1])           # 16 bit
        P_Time_2 = s.pack('!H', self.PAUSE_TIME[2])           # 16 bit
        P_Time_3 = s.pack('!H', self.PAUSE_TIME[3])           # 16 bit
        P_Time_4 = s.pack('!H', self.PAUSE_TIME[4])           # 16 bit
        P_Time_5 = s.pack('!H', self.PAUSE_TIME[5])           # 16 bit
        P_Time_6 = s.pack('!H', self.PAUSE_TIME[6])           # 16 bit
        P_Time_7 = s.pack('!H', self.PAUSE_TIME[7])           # 16 bit
        PAD_26_bytes = bytes(26)
        # CRC = s.pack('!I', 8888)
        p = Ether(dst=self.DMAC, src=self.SMAC, type=self.Ethertype) / MC_Opcode / PD / CE_Vector/ \
            P_Time_0 / P_Time_1 / P_Time_2 / P_Time_3 / P_Time_4 / P_Time_5 / P_Time_6 / P_Time_7 / \
            PAD_26_bytes
        print(bytes(p))
        CRC = s.pack('I', binascii.crc32(bytes(p)))
        P_crc = p / CRC
        print(P_crc)
        return P_crc


class link_pause_frame():
    SMAC = '00:0f:5d:30:41:50'
    DMAC = '01:80:C2:00:00:01'
    Ethertype = 0x8808
    MAC_control_Opcode = 0x0001
    PAUSE_TIME = 0x0000
    
    def __init__(self, pause_time):
        self.PAUSE_TIME = pause_time
    
    def set_pause_prio(self, pause_time):
        self.PAUSE_TIME = pause_time

    def unset_pause(self):
        self.PAUSE_TIME = 0

    def makepacket(self):
        MC_Opcode = s.pack('!H', self.MAC_control_Opcode)     # 16 bit
        P_Time = s.pack('!H', self.PAUSE_TIME)                # 16 bit
        PAD_bytes = bytes(42)
        p = Ether(dst=self.DMAC, src=self.SMAC, type=self.Ethertype) / MC_Opcode / P_Time / PAD_bytes
        print(bytes(p))
        CRC = s.pack('I', binascii.crc32(bytes(p)))
        P_crc = p / CRC
        print(P_crc)
        return P_crc


def mkpkt_pfc(num = 10, filename = '802.1Qbb.pcap'):
    packet = []
    for i in range(int(num)):
        packet.append(pfc_frame(1,65535).makepacket())
    wrpcap(filename, packet)

def mkpkt_link(num = 10, filename = '802.3X.pcap'):
    packet = []
    for i in range(int(num)):
        packet.append(link_pause_frame(65535).makepacket())
    wrpcap(filename, packet)


if __name__ == '__main__':
    mkpkt_pfc(1, '802.1Qbb.pcap')
    mkpkt_link(1, '802.3X.pcap')
