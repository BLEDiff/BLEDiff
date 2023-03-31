#
 #  Copyright (c) 2022 Imtiaz Karim & Abdullah Al Ishtiaq
 #  Modified from Swyentooth
 #  Licensed under the Apache License, Version 2.0 (the "License");
 #  you may not use this file except in compliance with the License.
 #  You may obtain a copy of the License at
 #
 #      http://www.apache.org/licenses/LICENSE-2.0
 #
 #  Unless required by applicable law or agreed to in writing, software
 #  distributed under the License is distributed on an "AS IS" BASIS,
 #  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 #  See the License for the specific language governing permissions and
 #  limitations under the License.
#

# Commom imports
import binascii
import time
import socket
import os
import time
import sys
import serial
from stat import *
import logging
import subprocess
from binascii import hexlify
import threading
import os
import sys
import inspect
import json
import logging
import traceback
from time import sleep, time
from serial import SerialException
import time
# PyCryptodome imports
from Crypto.Cipher import AES
from thread import *
import threading
# Flask imports
from flask import Flask, request
from flask_socketio import SocketIO
# Scapy imports
from scapy.layers.bluetooth import HCI_Hdr, L2CAP_Connection_Parameter_Update_Request, _att_error_codes
from scapy.layers.bluetooth4LE import *
from scapy.layers.bluetooth import *
from scapy.utils import wrpcap, raw
from scapy.packet import Raw

# BTLE Suite
from blesuite.pybt.att import AttributeProtocol
from blesuite.pybt.sm import SM, SecurityManagerProtocol
from blesuite.pybt.gatt import Server, UUID
from blesuite.entities.gatt_device import BLEDevice
import blesuite.utils.att_utils as att_utils
import blesuite.pybt.roles as ble_roles
import blesuite.pybt.gatt as PyBTGATT

# Colorama
from colorama import Fore, Back, Style
from colorama import init as colorama_init

from drivers.NRF52_dongle import NRF52Dongle
import BLESMPServer
from monitors.monitor_serial import Monitor

print_lock = threading.Lock()
device = None
acl_frag_flag = None
saved_ATT_Hdr = None
saved_pkt_with_ATT_Hdr = None
command = None



scan_response_received = False

conn_update = BTLE(access_addr=0x9a328370) / BTLE_DATA() / CtrlPDU() / LL_CONNECTION_UPDATE_REQ(win_size=2,
                                                                                                win_offset=2,
                                                                                                interval=46,  # 36 100
                                                                                                latency=0,
                                                                                                timeout=100,
                                                                                                instant=100
                                                                                                )

chm_update = BTLE(access_addr=0x9a328370) / BTLE_DATA() / CtrlPDU() / LL_CHANNEL_MAP_REQ(chM=0x1FF000000E,
                                                                                         instant=100
                                                                                         )


class BLECentralMethods(object):  # type: HierarchicalGraphMachine
    name = 'BLE'
    iterations = 0
    # Default Model paramaters
    master_address = None  # will take these inputs from a git ignored config file 
    slave_address = None    # will take these inputs from socket
    #master_feature_set = 'le_encryption+le_data_len_ext'  # Model dependent
    master_mtu = 247  # TODO: master_mtu
    conn_access_address = 0x5b431498
    conn_interval = 16
    conn_window_offset = 1
    conn_window_size = 2
    conn_channel_map = 0x1DDFFFFFFF
    conn_slave_latency = 0
    conn_timeout = 100
    dongle_serial_port = '/dev/ttyACM0'
    enable_fuzzing = False
    enable_duplication = False
    pairing_pin = '0000'
    scan_timeout = 6  # Time in seconds for detect a crash during scanning
    state_timeout = 3  # state timeout
    #pairing_iocap = 0x01  # DisplayYesNo
    #pairing_iocap = 0x01  # DisplayYesNo
    #pairing_iocap = 0x03  # NoInputNoOutput
    #pairing_iocap = 0x04  # KeyboardDisplay
    #paring_auth_request = 0x00  # No bonding
    #paring_auth_request = 0x01  # Bonding
    #paring_auth_request = 0x08 | 0x01  # Le Secure Connection + bonding
    #paring_auth_request = 0x04 | 0x01  # MITM + bonding
    #paring_auth_request = 0x08 | 0x40 | 0x01  # Le Secure Connection + MITM + bonding
    #paring_auth_request = 0xd  # Le Secure Connection + MITM + bonding
    # monitor_serial_port = '/dev/ttyUSB0'      # taking input from ble_config.json file
    monitor_serial_baud = 115200
    monitor_serial_magic_string = 'BLE Host Task Started'
    # -----------------------------------------------------------------------------------
    monitor = None
    # Timers for name reference
    conn_supervision_timer = None  # type: threading.Timer
    conn_general_timer = None  # type: threading.Timer
    scan_timeout_timer = None  # type: threading.Timer
    # Internal instances
    att = None
    smp = None  # type: SM
    driver = None  # type: NRF52Dongle
    # Internal variables
    master_address_raw = None
    slave_address_raw = None
    config_file = 'ble_config.json'
    addr_file = 'addr_config.json'
    iterations = 0
    master_address_type = None

    pkt_received = None
    pkt = None
    peer_address = None
    last_gatt_request = None
    empty_pdu_count = 0
    master_gatt_server = None
    sent_packet = None
    pairing_starting = False
    # Internal Slave params
    slave_address_type = None
    slave_feature_set = None
    slave_ble_version = None
    slave_next_start_handle = None
    slave_next_end_handle = None
    slave_service_idx = None
    slave_characteristic_idx = None
    slave_characteristic = None
    slave_device = None  # type: BLEDevice
    slave_handles = None
    slave_handles_values = None
    slave_handles_idx = None
    slave_ever_connected = False
    slave_connected = False
    slave_crashed = False
    slave_l2cap_fragment = []
    # Internal Encryption params
    conn_ltk = None
    conn_ediv = None
    conn_rand = None
    conn_iv = None
    conn_skd = None
    conn_session_key = None  # Used for LL Encryption
    conn_master_packet_counter = 0  # Packets counter for master (outgoing)
    conn_slave_packet_counter = 0  # Packets counter for slave (incoming)
    conn_encryted = False

    def __init__(self, machine_states, machine_transitions,
                #  master_address=None,
                 master_mtu=None,
                #  slave_address=None,
                 dongle_serial_port=None,
                 baudrate=None,
                 enable_fuzzing=None,
                 enable_duplication=None,
                 monitor_serial_port=None,
                 monitor_serial_baud=None,
                 monitor_magic_string=None,
                 client_socket=None):

        colorama_init(autoreset=True)  # Colors autoreset

        self.load_config()
        self.load_initial_addrs()

        self.client_socket = client_socket

        # Override loaded settings
        # if slave_address is not None:
        #     self.slave_address = slave_address

        # slave_address = self.slave_address

        # if master_address is not None:
        #     self.master_address = master_address

        if dongle_serial_port is not None:
            self.dongle_serial_port = dongle_serial_port

        if enable_fuzzing is not None:
            self.enable_fuzzing = enable_fuzzing

        if enable_duplication is not None:
            self.enable_duplication = enable_duplication

        if monitor_serial_port is not None:
            self.monitor_serial_port = monitor_serial_port

        if monitor_serial_baud is not None:
            self.monitor_serial_baud = monitor_serial_baud

        if monitor_magic_string is not None:
            self.monitor_serial_magic_string = monitor_magic_string

        if master_mtu is not None:
            self.master_mtu = master_mtu

        self.smp = SecurityManagerProtocol(self)
        BLESMPServer.set_pin_code(bytearray([(ord(byte) - 0x30) for byte in self.pairing_pin]))
        # BLESMPServer.set_local_key_distribution(0x07)

        self.master_gatt_server = self.create_gatt_server(mtu=master_mtu)
        self.att = AttributeProtocol(self, self.smp, event_hook=None, gatt_server=self.master_gatt_server,
                                     mtu=master_mtu)
        # self.master_address = master_address
        # self.slave_address = slave_address
        self.dongle_serial_port = dongle_serial_port
        self.baudrate = baudrate
        self.driver = NRF52Dongle(dongle_serial_port, baudrate)

        if self.master_address is not None:
            self.master_address_raw = ''.join(map(lambda x: chr(int(x, 16)), self.master_address.split(':')))
            self.master_address_type = ble_roles.PUBLIC_DEVICE_ADDRESS
        else:
            self.master_address_raw = os.urandom(6)
            self.master_address_type = ble_roles.RANDOM_DEVICE_ADDRESS

        self.peer_address = ''.join(self.slave_address.split(':'))
        self.slave_address_raw = ''.join(map(lambda x: chr(int(x, 16)), self.slave_address.split(':')))

        self.smp.initiate_security_manager_for_connection(self.peer_address,
                                                          ble_roles.PUBLIC_DEVICE_ADDRESS,
                                                          self.master_address_raw, self.master_address_type,
                                                          ble_roles.ROLE_TYPE_CENTRAL)



    def set_master_addr(self, new_master_addr):
        self.master_address = new_master_addr.lower()
        self.master_address_raw = ''.join(map(lambda x: chr(int(x, 16)), self.master_address.split(':')))

    def set_slave_addr(self, new_slave_addr):
        self.slave_address = new_slave_addr.lower()
        self.peer_address = ''.join(self.slave_address.split(':'))
        self.slave_address_raw = ''.join(map(lambda x: chr(int(x, 16)), self.slave_address.split(':')))

    def adjust_slave_addr(self, new_slave_addr):
        self.set_slave_addr(new_slave_addr)

        # TODO: check this part for correctness
        # reinitiate variables dependent on slave address
        self.smp = SecurityManagerProtocol(self)
        self.att = AttributeProtocol(self, self.smp, event_hook=None, gatt_server=self.master_gatt_server, mtu=self.master_mtu)
        self.smp.initiate_security_manager_for_connection(self.peer_address, 
                                                        ble_roles.PUBLIC_DEVICE_ADDRESS, 
                                                        self.master_address_raw, self.master_address_type,
                                                        ble_roles.ROLE_TYPE_CENTRAL)
        
    def load_initial_addrs(self):
        f = open(self.addr_file, 'r')
        obj = json.loads(f.read())
        f.close()

        self.set_master_addr(obj['MasterAddress'])
        self.set_slave_addr(obj['SlaveAddress'])
        self.master_address_type = obj['MasterAddressType']
        self.slave_address_type = obj['SlaveAddressType']



    def set_config(self, data):
        #self.conn_access_address = int(data['AccessAdress'], 16)
        self.conn_interval = int(data['ConnectionInterval'])
        self.conn_window_offset = int(data['WindowOffset'])
        self.conn_window_size = int(data['WindowSize'])
        self.conn_slave_latency = int(data['SlaveLatency'])
        #self.conn_channel_map = int(data['ChannelMap'], 16)
        self.conn_timeout = int(data['ConnectionTimeout'])
        self.master_feature_set = data['MasterFeatureSet']
        self.dongle_serial_port = data['DongleSerialPort']
        self.enable_fuzzing = bool(data['EnableFuzzing'])
        self.enable_duplication = bool(data['EnableDuplication'])
        self.pairing_pin = data['PairingPin']
        self.monitor_serial_port = data['MonitorSerialPort']
        self.monitor_serial_baud = int(data['MonitorSerialBaud'])


    def load_config(self):
        f = open(self.config_file, 'r')
        obj = json.loads(f.read())
        f.close()

        self.set_config(obj)
        
        return True



    # -------------------------------------------
    def state_change(self):
        if self.machine.source != self.machine.destination:
            self.update_timeout('conn_general_timer')
        self.empty_pdu_count = 0

    @staticmethod
    def create_gatt_server(mtu=23):
        gatt_server = Server(None)
        gatt_server.set_mtu(mtu)

        # Add Generic Access Service (https://www.bluetooth.com/specifications/gatt/services/)
        service_1 = gatt_server.generate_primary_gatt_service(PyBTGATT.UUID("1800"))
        # Add service to server
        gatt_server.add_service(service_1)
        # generate Device Name characteristic in service_1
        char1 = service_1.generate_and_add_characteristic('Greyhound',
                                                          PyBTGATT.GATT_PROP_READ | PyBTGATT.GATT_PROP_WRITE,
                                                          PyBTGATT.UUID("2A00"),
                                                          PyBTGATT.ATT_PROP_READ | PyBTGATT.ATT_PROP_WRITE,
                                                          PyBTGATT.ATT_SECURITY_MODE_OPEN,
                                                          PyBTGATT.ATT_SECURITY_MODE_NO_ACCESS, False)
        char1.generate_and_add_user_description_descriptor("Device Name")

        char1 = service_1.generate_and_add_characteristic('\x00\x00',
                                                          PyBTGATT.GATT_PROP_READ | PyBTGATT.GATT_PROP_WRITE,
                                                          PyBTGATT.UUID("2A01"),
                                                          PyBTGATT.ATT_PROP_READ | PyBTGATT.ATT_PROP_WRITE,
                                                          PyBTGATT.ATT_SECURITY_MODE_OPEN,
                                                          PyBTGATT.ATT_SECURITY_MODE_NO_ACCESS, False)
        char1.generate_and_add_user_description_descriptor("Appearance")

        char1 = service_1.generate_and_add_characteristic('\xFF\xFF\xFF\xFF\x00\x00\xFF\xFF',
                                                          PyBTGATT.GATT_PROP_READ | PyBTGATT.GATT_PROP_WRITE,
                                                          PyBTGATT.UUID("2A04"),
                                                          PyBTGATT.ATT_PROP_READ | PyBTGATT.ATT_PROP_WRITE,
                                                          PyBTGATT.ATT_SECURITY_MODE_OPEN,
                                                          PyBTGATT.ATT_SECURITY_MODE_NO_ACCESS, False)
        char1.generate_and_add_user_description_descriptor("Conn Paramaters")
        # -----

        # Add Immediate Alert Service (https://www.bluetooth.com/specifications/gatt/services/)
        service_1 = gatt_server.generate_primary_gatt_service(PyBTGATT.UUID("1802"))
        # Add service to server
        gatt_server.add_service(service_1)
        # generate Alert Level characteristic in service_1
        char1 = service_1.generate_and_add_characteristic('\x00',
                                                          PyBTGATT.GATT_PROP_READ | PyBTGATT.GATT_PROP_WRITE,
                                                          PyBTGATT.UUID("2A06"),
                                                          PyBTGATT.ATT_PROP_READ | PyBTGATT.ATT_PROP_WRITE,
                                                          PyBTGATT.ATT_SECURITY_MODE_OPEN,
                                                          PyBTGATT.ATT_SECURITY_MODE_NO_ACCESS, False)
        # add user description descriptor to characteristic
        char1.generate_and_add_user_description_descriptor("Characteristic 1")
        gatt_server.refresh_database()
        # gatt_server.debug_print_db()
        return gatt_server

    def save_ble_device(self):
        export_dict = self.slave_device.export_device_to_dictionary()
        device_json_output = json.dumps(export_dict, indent=4)
        f = open("bluetooth/device.json", "w")
        f.write(device_json_output)
        f.close()

    def update_slave_handles(self):
        if self.slave_handles:
            del self.slave_handles
        self.slave_handles = []

        if self.slave_handles_values:
            del self.slave_handles_values
        self.slave_handles_values = {}

        self.slave_handles_idx = 0
        for service in self.slave_device.services:
            self.slave_handles.append(service.start)
            for characteristic in service.characteristics:
                self.slave_handles.append(characteristic.handle)
                for descriptor in characteristic.descriptors:
                    self.slave_handles.append(descriptor.handle)

    @staticmethod
    def bt_crypto_e(key, plaintext):
        aes = AES.new(key, AES.MODE_ECB)
        return aes.encrypt(plaintext)

    def send(self, pkt):
        global command
        # if (self.slave_connected == False and BTLE_DATA in pkt):
        #    print(Fore.YELLOW + '[!] Skipping packets TX')
        #    return

        # if self.enable_fuzzing:
        #    fuzzing.fuzz_packet_by_layers(pkt, self.state, states_fuzzer_config, self)

        # if self.enable_duplication and (BTLE_DATA in pkt) and (LL_TERMINATE_IND not in pkt):
        #    fuzzing.repeat_packet(self)

        # if self.driver == None:
        #    return

        # if self.slave_crashed == False:
        #    self.machine.add_packets(
        #        NORDIC_BLE(board=75, protocol=2, flags=0x3, event_counter=self.driver.event_counter)
        #        / pkt)  # CRC ans master -> slave direction
        # self.sent_packet = pkt

        if pkt is None:
            return

        print(Fore.CYAN + "TX ---> " + pkt.summary()[7:])
        pkt.show()
        print("command: "+command)
        # pkt[BTLE].len = 0x72
        if "enc_pause_resp" in command:
            self.conn_encryted = False
        if self.conn_encryted is False or "discon_req" in command or "con_req" in command:
            # print(Fore.CYAN + "TX ---> " + pkt.summary()[7:])
            self.driver.raw_send(raw(pkt))
            # try:
            #     self.driver.raw_send(raw(pkt))
            # except:
            #     print(Fore.RED + "Fuzzing problem")
        else:
            self.send_encrypted(pkt)

    def send_encrypted(self, pkt):
        try:
            raw_pkt = bytearray(raw(pkt))
            access_address = raw_pkt[:4]
            header = raw_pkt[4]  # Get ble header
            length = raw_pkt[5] + 4  # add 4 bytes for the mic
            crc = '\x00\x00\x00'

            pkt_count = bytearray(struct.pack("<Q", self.conn_master_packet_counter)[:5])  # convert only 5 bytes
            pkt_count[4] |= 0x80  # Set for master -> slave
            if self.conn_iv is None or self.conn_session_key is None:
                return
            nonce = pkt_count + self.conn_iv

            aes = AES.new(self.conn_session_key, AES.MODE_CCM, nonce=nonce, mac_len=4)  # mac = mic

            aes.update(chr(header & 0xE3))  # Calculate mic over header cleared of NES, SN and MD

            enc_pkt, mic = aes.encrypt_and_digest(raw_pkt[6:-3])  # get payload and exclude 3 bytes of crc
            print("$$$$$$$$$$$$$$$$$$$$$$$")
            print("sending encrypted stuffffff!!!!!")
            self.driver.raw_send(access_address + chr(header) + chr(length) + enc_pkt + mic + crc)
            self.conn_master_packet_counter += 1
        except:
            print ("Can not send!")

    def receive_encrypted(self, pkt):
        raw_pkt = bytearray(raw(pkt))
        access_address = raw_pkt[:4]
        header = raw_pkt[4]  # Get ble header
        length = raw_pkt[5]  # add 4 bytes for the mic

        if length is 0 or length < 5:
            # ignore empty PDUs
            return pkt
        # Subtract packet length 4 bytes of MIC
        length -= 4

        # Update nonce before decrypting
        pkt_count = bytearray(struct.pack("<Q", self.conn_slave_packet_counter)[:5])  # convert only 5 bytes
        pkt_count[4] &= 0x7F  # Clear bit 7 for slave -> master
        if self.conn_session_key is None or self.conn_iv is None or pkt is None:
            return

        nonce = pkt_count + self.conn_iv


        aes = AES.new(self.conn_session_key, AES.MODE_CCM, nonce=nonce, mac_len=4)  # mac = mic
        aes.update(chr(header & 0xE3))  # Calculate mic over header cleared of NES, SN and MD

        dec_pkt = aes.decrypt(raw_pkt[6:-4 - 3])  # get payload and exclude 3 bytes of crc

        try:
            mic = raw_pkt[6 + length: -3]  # Get mic from payload and exclude crc
            aes.verify(mic)
            self.conn_slave_packet_counter += 1
            return BTLE(access_address + chr(header) + chr(length) + dec_pkt + '\x00\x00\x00')
        except:
            print(Fore.RED + "MIC Wrong")
            self.conn_slave_packet_counter += 1
            p = BTLE(access_address + chr(header) + chr(length) + dec_pkt + '\x00\x00\x00')
            # self.machine.report_anomaly(msg='MIC Wrong', pkt=p)
            return None

    # Ble Suite bypass functions
    ff = 0

    def raw_att(self, attr_data, conn_handle, length):
        if self.driver:
            pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / attr_data
            # pkt[BTLE_DATA].LLID = 0
            # pkt[BTLE_DATA].len = 7
            # pkt[L2CAP_Hdr].len = 3
            # pkt.len = 100  # Crash fitbit/Cypress fastly

            self.send(pkt)
            # self.send(pkt)
            # self.send(pkt)
            # self.send(pkt)
            # self.send(pkt)

            # if ATT_Read_By_Type_Request and self.state == 'CHARACTERISTICS':  # This Crashes ESP32
            #     print(pkt.command())
            #     self.ff += 1
            #     if self.ff == 2:  # 1 or 2 here
            #         self.ff = 0
            #         print(Fore.YELLOW + 'Sending out of order packet with wrong mic')
            #         self.conn_encryted = False  # this disables encryption
            #         # self.send_disconn_request()
            #         # self.send_disconn_request()
            #         self.send_version_indication()

            # self.send(pkt)
            # if ATT_Read_By_Type_Request in pkt:
            #     self.send(pkt)

    def raw_smp(self, smp_data, conn_handle, length):
        if self.driver:
            pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / smp_data
            self.send(pkt)

    def reset_dongle_connection(self):
        self.driver.reset()
        
    def reset_vars(self):
        global scan_response_received
        global saved_ATT_Hdr
        global saved_pkt_with_ATT_Hdr
        scan_response_received = False
        self.slave_l2cap_fragment = []
        self.empty_pdu_count = 0
        saved_ATT_Hdr = None
        saved_pkt_with_ATT_Hdr = None
        self.conn_encryted = False
        self.sent_packet = None
        self.conn_master_packet_counter = 0
        self.conn_slave_packet_counter = 0
        self.slave_next_start_handle = None
        self.slave_next_end_handle = None
        self.slave_service_idx = None
        self.slave_characteristic_idx = None
        self.slave_characteristic = None
        self.pairing_starting = False
        self.slave_connected = False
        self.slave_crashed = False
        self.name = 'BLE'
        # Default Model paramaters
        #self.master_feature_set = 'le_encryption+le_data_len_ext'  # Model dependent
        self.master_mtu = 247  # TODO: master_mtu
        #self.conn_access_address = 0x5a328372
        self.conn_interval = 16
        self.conn_window_offset = 1
        self.conn_window_size = 2
        #self.conn_channel_map = 0x1FFFFFFFFF
        self.conn_slave_latency = 0
        self.conn_timeout = 100
        self. dongle_serial_port = '/dev/ttyACM0'
        self.enable_fuzzing = False
        self.enable_duplication = False
        self. pairing_pin = '0000'
        self.scan_timeout = 6  # Time in seconds for detect a crash during scanning
        self.state_timeout = 3  # state timeout
        #self.pairing_iocap = 0x01  # DisplayYesNo
        #self.pairing_iocap = 0x03  # NoInputNoOutput
        # pairing_iocap = 0x04  # KeyboardDisplay
        # paring_auth_request = 0x00  # No bonding
        # paring_auth_request = 0x01  # Bonding
        #self.paring_auth_request = 0x08 | 0x01  # Le Secure Connection + bonding
        # paring_auth_request = 0x04 | 0x01  # MITM + bonding
        # paring_auth_request = 0x08 | 0x40 | 0x01  # Le Secure Connection + MITM + bonding
        # monitor_serial_port = '/dev/ttyUSB0'      # taking input from ble_config.json file
        self.monitor_serial_baud = 115200
        self.monitor_serial_magic_string = 'BLE Host Task Started'
        # -----------------------------------------------------------------------------------
        self.monitor = None
        # Timers for name reference
        self.conn_supervision_timer = None  # type: threading.Timer
        self.conn_general_timer = None  # type: threading.Timer
        self.scan_timeout_timer = None  # type: threading.Timer
        # Internal instances
        # Internal variables

        self.pkt_received = None
        self.pkt = None
        self.peer_address = None
        self.last_gatt_request = None
        self.empty_pdu_count = 0
        self.master_gatt_server = None
        self.sent_packet = None
        self.pairing_starting = False
        # Internal Slave params
        self.slave_address_type = None
        self.slave_feature_set = None
        self.slave_ble_version = None
        self.slave_next_start_handle = None
        self.slave_next_end_handle = None
        self.slave_service_idx = None
        self.slave_characteristic_idx = None
        self.slave_characteristic = None
        self.slave_device = None  # type: BLEDevice
        #self.slave_handles = None
        #self.slave_handles_values = None
        #self.slave_handles_idx = None
        self.slave_ever_connected = False
        self.slave_connected = False
        self.slave_crashed = False
        self.slave_l2cap_fragment = []
        # Internal Encryption params
        self.conn_ltk = None
        self.conn_ediv = None
        self.conn_rand = None
        self.conn_iv = None
        self.conn_skd = None
        self.conn_session_key = None  # Used for LL Encryption
        self.conn_master_packet_counter = 0  # Packets counter for master (outgoing)
        self.conn_slave_packet_counter = 0  # Packets counter for slave (incoming)
        self.conn_encryted = False
        print("self.master_address: " + str(self.master_address))
        self.master_address = str(RandMAC()).upper()
        print("self.master_address: " + str(self.master_address))
        self.master_address_raw = ''.join(map(lambda x: chr(int(x, 16)), self.master_address.split(':')))
        '''
        self.master_address_raw = os.urandom(6)
        self.master_address_type = ble_roles.RANDOM_DEVICE_ADDRESS

        self.peer_address = ''.join(self.slave_address.split(':'))
        self.slave_address_raw = ''.join(map(lambda x: chr(int(x, 16)), self.slave_address.split(':')))
        print("self.peer_address: "+ self.peer_address)
        print("ble_roles.PUBLIC_DEVICE_ADDRESS: " + str(ble_roles.PUBLIC_DEVICE_ADDRESS))
        print("self.master_address_raw: " + self.master_address_raw)
        print("self.self.master_address_type: " + str(self.master_address_type))
        self.smp.initiate_security_manager_for_connection(self.peer_address,
                                                          ble_roles.PUBLIC_DEVICE_ADDRESS,
                                                          self.master_address_raw, self.master_address_type,
                                                          ble_roles.ROLE_TYPE_CENTRAL)
        '''

    def timeout_detected(self):
        # self.machine.reset_state_timeout()
        self.disable_timeout('conn_supervision_timer')
        self.disable_timeout('conn_general_timer')
        # self.start_timeout('scan_timeout_timer', self.scan_timeout, self.scan_timeout_detected)
        print(Fore.LIGHTRED_EX + '[TIMEOUT] !!! Link timeout detected !!!')
        # print(Fore.YELLOW + 'Reseting model to state ' + self.machine.idle_state)
        # self.machine.reset_machine()
        # self.reset_vars()
        # self.machine.save_packets()

    def timeout_transition_detected(self):
        self.machine.reset_state_timeout()
        self.disable_timeout('conn_supervision_timer')
        self.disable_timeout('conn_general_timer')
        self.start_timeout('scan_timeout_timer', self.scan_timeout, self.scan_timeout_detected)
        print(Fore.YELLOW + '[TIMEOUT] !!! State global timeout !!!')
        print(Fore.YELLOW + 'Reseting model to state ' + self.machine.idle_state)
        self.machine.reset_machine()
        self.reset_vars()
        self.machine.save_packets()

    def scan_timeout_detected(self):
        if self.slave_ever_connected:
            self.disable_timeout('conn_general_timer')
            self.machine.report_crash()
            self.slave_ever_connected = False
            self.reset_vars()
            self.machine.save_packets()
            self.slave_crashed = True

    def disable_timeout(self, timer_name):
        timer = getattr(self, timer_name)
        if timer:
            timer.cancel()
            setattr(self, timer_name, None)

    def update_timeout(self, timer_name):
        timer = getattr(self, timer_name)
        if timer:
            timer.cancel()
            self.start_timeout(timer_name, timer.interval, timer.function)

    def start_timeout(self, timer_name, seconds, callback):
        timer = getattr(self, timer_name)
        timer = threading.Timer(seconds, callback)
        setattr(self, timer_name, timer)
        timer.daemon = True
        timer.start()

    def announce_connection(self):
        self.disable_timeout('scan_timeout_timer')
        # self.start_timeout('conn_supervision_timer', self.conn_timeout / 100.0, self.timeout_detected)
        # self.start_timeout('conn_general_timer', self.state_timeout, self.timeout_transition_detected)
        print(Fore.GREEN + '[!] BLE Connection Established to target device')
        print(Fore.GREEN + '[!] Supervision timeout set to ' + str(self.conn_timeout / 100.0) + ' seconds')
        self.slave_ever_connected = True  # used to detect first connection
        self.slave_connected = True  # used to detect first connection

    def announce_disconnection(self):
        self.disable_timeout('conn_supervision_timer')
        self.disable_timeout('conn_general_timer')
        # self.start_timeout('scan_timeout_timer', self.scan_timeout, self.scan_timeout_detected)
        self.machine.save_packets()
        self.reset_vars()
        print(Fore.YELLOW + '[!] Disconnected from target device')



    # Receive functions
    def sniff(self, timeout = 2):


        # self.retry()
        # timeout variable can be omitted, if you use specific value in the while condition
        # timeout = 2  # [seconds]
        print(Fore.YELLOW + '[!] BLE Sniffing started... ')
        timeout_start = time.time()
        out = 0
        while time.time() < timeout_start + timeout:
            try:
                if self.driver:

                    while time.time() < timeout_start + timeout:
                        data = self.driver.raw_receive()
                        if data:
                            pkt = BTLE(data)
                            out = self.receive_packet(pkt)
                            #print("value of out is: "+str(out))
                            #if out == 1:
                             #break
                    #if out == 1:
                     #break


            except KeyboardInterrupt:
                print(Fore.RED + 'Model process stopped' + Fore.RESET)
                exit(0)
            except SerialException:
                self.driver = None
                print(Fore.RED + 'Serial busy' + Fore.RESET)

            '''
            try:
                print(Fore.RED + 'Recovering' + Fore.RESET)
                self.disable_timeout('scan_timeout_timer')
                sleep(2)  # Sleep 1 second and retry
                self.driver = NRF52Dongle(self.dongle_serial_port, 1000000)
            except KeyboardInterrupt:
                print(Fore.RED + 'Model process stopped' + Fore.RESET)
                exit(0)
            except SerialException:
                pass
            '''

    def receive_packet(self, pkt):
        # self.update_timeout('conn_supervision_timer')
        global scan_response_received
        global saved_ATT_Hdr
        global saved_pkt_with_ATT_Hdr
        global command
        print_lines = False
        append_current_pkt = True
        pkts_to_process = []

        # Decrypt packet if link is encrypted

        if self.conn_encryted:
            pkt = self.receive_encrypted(pkt)
            if pkt is None:
                # Integrity check fail. Drop packet to not cause validation confusion
                return

        # Handle L2CAP fragment
        if (BTLE_DATA in pkt and pkt.len != 0) and (pkt.LLID == 0x02 or pkt.LLID == 0x01):
            if pkt.LLID == 0x01 or len(self.slave_l2cap_fragment) == 0:
                self.slave_l2cap_fragment.append(pkt)
                return
            append_current_pkt = False
            self.slave_l2cap_fragment.append(pkt)

        if len(self.slave_l2cap_fragment) > 0:
            p_full = raw(self.slave_l2cap_fragment[0])[:-3]  # Get first raw l2cap start frame
            self.slave_l2cap_fragment.pop(0)  # remove it from list
            idx = 0
            for frag in self.slave_l2cap_fragment:
                if frag.LLID == 0x02:
                    break
                p_full += raw(frag[BTLE_DATA].payload)  # Get fragment bytes
                idx += 1
                # print(Fore.YELLOW + 'fragment')

            del self.slave_l2cap_fragment[:idx]
            p = BTLE(p_full + '\x00\x00\x00')
            p.len = len(p[BTLE_DATA].payload)  # update ble header length
            pkts_to_process.append(p)  # joins all fragements

        # Add currently received packet
        if append_current_pkt:
            pkts_to_process.append(pkt)

        # Process packts in the packet list
        for pkt in pkts_to_process:
            # If packet is not an empty pdu or a termination indication
            if Raw in pkt:
                continue
            if (BTLE_EMPTY_PDU not in pkt) and (LL_TERMINATE_IND not in pkt) and (
                    L2CAP_Connection_Parameter_Update_Request not in pkt) and (
                    BTLE_DATA in pkt or (
                    (BTLE_ADV_IND in pkt or BTLE_SCAN_RSP in pkt) and pkt.AdvA == self.slave_address)):
                # Print packet
                print(Fore.CYAN + "RX <--- " + pkt.summary())
                # pkt.show()
                # packet = pkt.summary()[7:]
                print_lines = True

                self.pkt_received = True
                self.pkt = pkt
    
                if ATT_Hdr in pkt:
                    saved_ATT_Hdr = ATT_Hdr
                    saved_pkt_with_ATT_Hdr = pkt
                if LL_TERMINATE_IND in pkt:
                    print(Fore.YELLOW + "[!] LL_TERMINATE_IND received. Disconnecting from the slave...")
                    self.disable_timeout('conn_supervision_timer')
                    self.disable_timeout('conn_general_timer')
                    self.reset_vars()

                if "BTLE_ADV / BTLE_ADV_IND" in pkt.summary():
                    print("Received advertising indications")
                    if "steval" in device or "bluez" in device:
                        self.client_socket.send("adv_ind\n")
                if "BTLE_ADV / BTLE_SCAN_RSP" in pkt.summary():
                    print("Received scan response")
                    self.client_socket.send("scan_resp\n")
                    self.receive_scan_response()
                    scan_response_received = True

                if "BTLE_DATA / CtrlPDU / LL_SLAVE_FEATURE_REQ" in pkt.summary():
                    print("Received feature request")
                    self.client_socket.send("feature_req\n")
                    self.receive_feature_request()
                    self.send_feature_response()
                        #return 1
                if "BTLE_DATA / CtrlPDU / LL_LENGTH_REQ" in pkt.summary():
                    print("Received length request")
                    #self.client_socket.send("length_req\n")
                    self.receive_length_request()
                    self.send_length_response()
                if "BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Exchange_MTU_Request" in pkt.summary():
                    print("Received MTU request")
                    self.client_socket.send("mtu_req\n")
                    self.receive_mtu_length_request()
                    self.send_mtu_length_response()

                if "BTLE_DATA / CtrlPDU / LL_LENGTH_RSP" in pkt.summary():
                    print("Received length response")
                    self.client_socket.send("length_resp\n")
                    self.receive_length_response()

                if "BTLE / BTLE_DATA / CtrlPDU / LL_REJECT_IND" in pkt.summary():
                    print("received LL reject\n")
                    self.client_socket.send("ll_reject\n")

                if "BTLE / BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Read_By_Group_Type_Request" in pkt.summary():
                    print("Recieved PRI Request from OTA")
                    #self.client_socket.send("pri_req\n")
                    self.send_pri_services_response()
                    # self.receive_pri_services()     #TODO: check

                if "BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Read_By_Type_Request" in pkt.summary():
                    print("Received read type request")
                    #self.client_socket.send("char_req\n")
                if "BTLE / BTLE_DATA / CtrlPDU / LL_VERSION_IND" in pkt.summary():
                    print("Received version response from OTA")
                    self.client_socket.send("version_resp\n")
                    self.receive_version_indication()
                    if "version_req" not in command:
                        self.send_version_indication()

                if "BTLE / BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Exchange_MTU_Response" in pkt.summary():
                    print("Received mtu_resp from OTA")
                    pkt.show()
                    self.client_socket.send("mtu_resp\n")
                    self.receive_mtu_length_response()
                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Pairing_Response" in pkt.summary():
                    print("Received Pairing Response from OTA")
                    auth_value = pkt[SM_Pairing_Response].authentication
                    auth_value = auth_value & 0b0010
                    #print(type(auth_value))
                    print(auth_value)
                    print(type(auth_value))
                    if "pair_req_no_sc" in command:
                        print("sending pair_resp_no_sc")
                        self.client_socket.send("pair_resp_no_sc\n")
                    else:
                        print("sending pair_resp")
                        self.client_socket.send("pair_resp\n")
                    self.finish_pair_response()

                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Public_Key" in pkt.summary():
                    print("Received public_key_response from OTA")

                    self.pkt.show()
                    self.finish_key_exchange()
                    self.client_socket.send("public_key_response\n")

                if "BTLE_DATA / CtrlPDU / LL_FEATURE_RSP" in pkt.summary():
                    print("Received feature response")
                    self.client_socket.send("feature_resp\n")
                    self.receive_feature_response()

                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Confirm" in pkt.summary():
                    print("Received sm_confirm from OTA")
                    self.client_socket.send("sm_confirm\n")
                    self.finish_pair_response()

                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Random" in pkt.summary():
                    print("Received sm_random_received from OTA")

                    self.finish_pair_response()
                    self.client_socket.send("sm_random_received\n")

                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_DHKey_Check" in pkt.summary():
                    print("Received dh_key_response from OTA")
                    self.finish_pair_response()
                    self.client_socket.send("dh_key_response\n")

                if "BTLE / BTLE_DATA / CtrlPDU / LL_ENC_RSP" in pkt.summary():
                    print("Recieved Encryption Response from OTA")
                    self.client_socket.send("enc_resp\n")
                    self.receive_encryption_response()
                if "BTLE / BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Read_By_Group_Type_Response" in pkt.summary():
                    print("Recieved pri_resp from OTA")
                    self.client_socket.send("pri_resp\n")
                    self.receive_pri_services()
                if "BTLE / BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Read_By_Type_Response" in pkt.summary():
                    print("received char_resp from OTA")
                    print("command: "+str(command))
                    self.client_socket.send("char_resp\n")
                    if "char_req" in command:
                        self.receive_characteristics()
                    else:
                        self.receive_includes()
                    #self.receive_descriptors()
                if "BTLE / BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Error_Response" in pkt.summary():
                    print("received att_error")
                    self.client_socket.send("att_error\n")
                if "BTLE / BTLE_DATA / CtrlPDU / LL_START_ENC_REQ" in pkt.summary():
                    print("Recieved Start Encryption Request from OTA")
                    self.client_socket.send("start_enc_req\n")
                    self.receive_encryption_response()
                if "BTLE / BTLE_DATA / CtrlPDU / LL_START_ENC_RSP" in pkt.summary():
                    print("Recieved Start Encryption Response from OTA")
                    self.client_socket.send("start_enc_resp\n")
                    self.receive_encryption_response()
                    # self.send_sec_services_request()
                if "BTLE / BTLE_DATA / CtrlPDU / LL_PAUSE_ENC_RSP" in pkt.summary():
                    print("Recieved Encryption Pause Response from OTA")
                    self.client_socket.send("enc_pause_resp\n")
                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Signing_Information" in pkt.summary():
                    self.pkt.show()
                    print("Recieved SM_Signing_Information from OTA")
                    self.finish_keys()

                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Identity_Information" in pkt.summary():
                    self.pkt.show()
                    print("Recieved SM_Signing_Information from OTA")
                    self.finish_keys()

                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Identity_Address_Information" in pkt.summary():
                    self.pkt.show()
                    print("Recieved SM_Signing_Information from OTA")
                    self.finish_keys()


                if "BTLE / BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Find_Information_Response" in pkt.summary():
                    print("received desc_resp from OTA")
                    self.client_socket.send("desc_resp\n")
                    self.receive_descriptors()
                if "BTLE / BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Read_Response" in pkt.summary():
                    print("received read response")
                    self.client_socket.send("read_resp\n")
                    self.finish_readings()
                if "BTLE / BTLE_DATA / L2CAP_Hdr / ATT_Hdr / ATT_Write_Response" in pkt.summary():
                    print("received write response")
                    self.client_socket.send("write_resp\n")
                    self.finish_writing()
                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Failed" in pkt.summary():
                    # print(pkt.summary())
                    # self.client_socket.send("write_resp\n")
                    # self.finish_writing()
                    pkt.show()
                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Security_Request" in pkt.summary():
                    pkt.show()
                    print("received SM_Security_Request")
                    self.client_socket.send("sec_req\n")
                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Encryption_Information" in pkt.summary():
                    print("received SM_Encryption_Information")
                    pkt.show()
                    self.conn_ltk = pkt.ltk
                    print(Fore.GREEN + "[!] LTK received from OTA: " + hexlify(self.conn_ltk).upper())
                    self.finish_keys()
                if "BTLE / BTLE_DATA / L2CAP_Hdr / SM_Hdr / SM_Master_Identification" in pkt.summary():
                    print("received SM_Master_Identification")
                    pkt.show()
                    self.conn_ediv = pkt.ediv
                    self.conn_rand = pkt.rand
                    self.finish_keys()

        if print_lines:
            print('----------------------------')
            return 1

    def version_already_received(self):
        if self.slave_ble_version is not None:
            return True
        return False

    def send_pri_services_response(self):
        self.att.read_by_group_type_resp(0x0000, "", None)

    def send_scan_request(self):

#         self.master_address_type = 0
#         self.slave_address_type = 0
        self.conn_encryted = False
        pkt = BTLE() / BTLE_ADV(RxAdd=self.slave_address_type, TxAdd=self.master_address_type) / BTLE_SCAN_REQ(
            ScanA=self.master_address,
            AdvA=self.slave_address)
        print('Master Type: ' + str(self.master_address_type))
        print('Slave Type: ' + str(self.slave_address_type))
        print('Master: ' + str(self.master_address))
        print('Slave: ' + str(self.slave_address))
        # pkt.Length = 14
        # pkt.Length = 6
        # pkt.AdvA = '7f:4d:e5:00:00:00'
        # pkt.ScanA = '00:00:00:00:21:09'
        # pkt.PDU_type = 0x0d
        self.send(pkt)

        print(Fore.YELLOW + 'Waiting advertisements from ' + self.slave_address)
        #self.driver.set_jamming(1)

    def receive_scan_response(self):
        if self.pkt_received:

            if (BTLE_ADV_NONCONN_IND in self.pkt or BTLE_ADV_IND in self.pkt or BTLE_SCAN_RSP in self.pkt) and \
                    self.pkt.AdvA == self.slave_address.lower():

                # self.disable_timeout('scan_timeout_timer')
                # self.start_timeout('scan_timeout_timer', self.scan_timeout, self.scan_timeout_detected)

                if BTLE_ADV_IND in self.pkt and self.slave_address_type != self.pkt.TxAdd:
                    self.slave_address_type = self.pkt.TxAdd  # Get slave address type
                    self.send_scan_request()  # Send scan request again
                else:
                    self.slave_address_type = self.pkt.TxAdd
                    return True

                return True
        return False

    switch = 0

    def send_connection_request(self):
        self.slave_feature_set = None
        self.slave_ble_version = None

        # TODO: enable or disable random address
        #self.master_address = str(RandMAC()).upper()
        #self.master_address_raw = ''.join(map(lambda x: chr(int(x, 16)), self.master_address.split(':')))

        pkt = BTLE() / BTLE_ADV(RxAdd=self.slave_address_type, TxAdd=self.master_address_type) / BTLE_CONNECT_REQ(
            InitA=self.master_address,
            AdvA=self.slave_address,
            AA=self.conn_access_address,
            crc_init=0x179a9c,
            win_size=self.conn_window_size,
            win_offset=self.conn_window_offset,
            interval=self.conn_interval,  # 36
            latency=self.conn_slave_latency,
            timeout=self.conn_timeout,
            chM=self.conn_channel_map,
            hop=5,
            SCA=0,
        )

        self.conn_access_address = pkt.AA

        if self.slave_device:
            del self.slave_device
        self.slave_device = BLEDevice()

        # pkt[BTLE_ADV].Length = 18  # Crash Texas CC2540
        # pkt[BTLE_ADV].interval = 0  # Crash Texas CC2540
        # pkt[BTLE_ADV].timeout = 0  # Crash Texas CC2540
        self.send(pkt)


    def send_connection_request_hop_zero(self):
        self.slave_feature_set = None
        self.slave_ble_version = None

        # TODO: enable or disable random address
        #self.master_address = str(RandMAC()).upper()
        #self.master_address_raw = ''.join(map(lambda x: chr(int(x, 16)), self.master_address.split(':')))

        pkt = BTLE() / BTLE_ADV(RxAdd=self.slave_address_type, TxAdd=self.master_address_type) / BTLE_CONNECT_REQ(
            InitA=self.master_address,
            AdvA=self.slave_address,
            AA=self.conn_access_address,
            crc_init=0x179a9c,
            win_size=self.conn_window_size,
            win_offset=self.conn_window_offset,
            interval=self.conn_interval,  # 36
            latency=self.conn_slave_latency,
            timeout=self.conn_timeout,
            chM=self.conn_channel_map,
            hop=0,
            SCA=0,
        )

        self.conn_access_address = pkt.AA

        if self.slave_device:
            del self.slave_device
        self.slave_device = BLEDevice()

        # pkt[BTLE_ADV].Length = 18  # Crash Texas CC2540
        # pkt[BTLE_ADV].interval = 0  # Crash Texas CC2540
        # pkt[BTLE_ADV].timeout = 0  # Crash Texas CC2540
        self.send(pkt)

    def send_connection_request_crc_zero(self):
        self.slave_feature_set = None
        self.slave_ble_version = None

        # TODO: enable or disable random address
        #self.master_address = str(RandMAC()).upper()
        #self.master_address_raw = ''.join(map(lambda x: chr(int(x, 16)), self.master_address.split(':')))

        pkt = BTLE() / BTLE_ADV(RxAdd=self.slave_address_type, TxAdd=self.master_address_type) / BTLE_CONNECT_REQ(
            InitA=self.master_address,
            AdvA=self.slave_address,
            AA=self.conn_access_address,
            crc_init=0x0000,
            win_size=self.conn_window_size,
            win_offset=self.conn_window_offset,
            interval=self.conn_interval,  # 36
            latency=self.conn_slave_latency,
            timeout=self.conn_timeout,
            chM=self.conn_channel_map,
            hop=5,
            SCA=0,
        )

        self.conn_access_address = pkt.AA

        if self.slave_device:
            del self.slave_device
        self.slave_device = BLEDevice()

        # pkt[BTLE_ADV].Length = 18  # Crash Texas CC2540
        # pkt[BTLE_ADV].interval = 0  # Crash Texas CC2540
        # pkt[BTLE_ADV].timeout = 0  # Crash Texas CC2540
        self.send(pkt)

    def send_connection_request_channel_map_zero(self):
        self.slave_feature_set = None
        self.slave_ble_version = None

        # TODO: enable or disable random address
        #self.master_address = str(RandMAC()).upper()
        #self.master_address_raw = ''.join(map(lambda x: chr(int(x, 16)), self.master_address.split(':')))

        pkt = BTLE() / BTLE_ADV(RxAdd=self.slave_address_type, TxAdd=self.master_address_type) / BTLE_CONNECT_REQ(
            InitA=self.master_address,
            AdvA=self.slave_address,
            AA=self.conn_access_address,
            crc_init=0x179a9c,
            win_size=self.conn_window_size,
            win_offset=self.conn_window_offset,
            interval=self.conn_interval,  # 36
            latency=self.conn_slave_latency,
            timeout=self.conn_timeout,
            chM=0x00,
            hop=5,
            SCA=0,
        )

        self.conn_access_address = pkt.AA

        if self.slave_device:
            del self.slave_device
        self.slave_device = BLEDevice()

        # pkt[BTLE_ADV].Length = 18  # Crash Texas CC2540
        # pkt[BTLE_ADV].interval = 0  # Crash Texas CC2540
        # pkt[BTLE_ADV].timeout = 0  # Crash Texas CC2540
        self.send(pkt)


    def send_connection_request_length_zero(self):
        self.slave_feature_set = None
        self.slave_ble_version = None

        # TODO: enable or disable random address
        #self.master_address = str(RandMAC()).upper()
        #self.master_address_raw = ''.join(map(lambda x: chr(int(x, 16)), self.master_address.split(':')))

        pkt = BTLE() / BTLE_ADV(RxAdd=self.slave_address_type, TxAdd=self.master_address_type) / BTLE_CONNECT_REQ(
            InitA=self.master_address,
            AdvA=self.slave_address,
            AA=self.conn_access_address,
            crc_init=0x179a9c,
            win_size=self.conn_window_size,
            win_offset=self.conn_window_offset,
            interval=self.conn_interval,  # 36
            latency=self.conn_slave_latency,
            timeout=self.conn_timeout,
            chM=self.conn_channel_map,
            hop=5,
            SCA=0,
        )

        self.conn_access_address = pkt.AA

        if self.slave_device:
            del self.slave_device
        self.slave_device = BLEDevice()

        pkt[BTLE_ADV].Length = 0  # Crash Texas CC2540
        # pkt[BTLE_ADV].interval = 0  # Crash Texas CC2540
        # pkt[BTLE_ADV].timeout = 0  # Crash Texas CC2540
        self.send(pkt)

    def send_connection_request_interval_zero(self):
        self.slave_feature_set = None
        self.slave_ble_version = None

        # TODO: enable or disable random address
        #self.master_address = str(RandMAC()).upper()
        #self.master_address_raw = ''.join(map(lambda x: chr(int(x, 16)), self.master_address.split(':')))

        pkt = BTLE() / BTLE_ADV(RxAdd=self.slave_address_type, TxAdd=self.master_address_type) / BTLE_CONNECT_REQ(
            InitA=self.master_address,
            AdvA=self.slave_address,
            AA=self.conn_access_address,
            crc_init=0x179a9c,
            win_size=self.conn_window_size,
            win_offset=self.conn_window_offset,
            interval=self.conn_interval,  # 36
            latency=self.conn_slave_latency,
            timeout=self.conn_timeout,
            chM=self.conn_channel_map,
            hop=5,
            SCA=0,
        )

        self.conn_access_address = pkt.AA

        if self.slave_device:
            del self.slave_device
        self.slave_device = BLEDevice()

        # pkt[BTLE_ADV].Length = 18  # Crash Texas CC2540
        pkt[BTLE_ADV].interval = 0  # Crash Texas CC2540
        # pkt[BTLE_ADV].timeout = 0  # Crash Texas CC2540
        self.send(pkt)


    def send_connection_request_timeout_zero(self):
        self.slave_feature_set = None
        self.slave_ble_version = None

        # TODO: enable or disable random address
        #self.master_address = str(RandMAC()).upper()
        #self.master_address_raw = ''.join(map(lambda x: chr(int(x, 16)), self.master_address.split(':')))

        pkt = BTLE() / BTLE_ADV(RxAdd=self.slave_address_type, TxAdd=self.master_address_type) / BTLE_CONNECT_REQ(
            InitA=self.master_address,
            AdvA=self.slave_address,
            AA=self.conn_access_address,
            crc_init=0x179a9c,
            win_size=self.conn_window_size,
            win_offset=self.conn_window_offset,
            interval=self.conn_interval,  # 36
            latency=self.conn_slave_latency,
            timeout=self.conn_timeout,
            chM=self.conn_channel_map,
            hop=5,
            SCA=0,
        )

        self.conn_access_address = pkt.AA

        if self.slave_device:
            del self.slave_device
        self.slave_device = BLEDevice()

        # pkt[BTLE_ADV].Length = 18  # Crash Texas CC2540
        # pkt[BTLE_ADV].interval = 0  # Crash Texas CC2540
        pkt[BTLE_ADV].timeout = 0  # Crash Texas CC2540
        self.send(pkt)

    def send_gatt_response(self):
        if self.last_gatt_request is None:
            pkt = self.pkt
            self.last_gatt_request = pkt
        else:
            pkt = self.last_gatt_request

        self.att.marshall_request(None, pkt[ATT_Hdr], self.peer_address)
        # self.sent_packet.show()

    def receive_gatt_request(self):
        if ATT_Hdr in self.pkt:
            return True
        return False

    def handle_gatt_response(self):
        if ATT_Hdr in self.pkt:
            self.last_gatt_request = self.pkt
            self.att.marshall_request(None, self.pkt[ATT_Hdr], self.peer_address)
            self.last_gatt_request = None
            if ATT_Error_Response in self.sent_packet:
                # self.last_gatt_request = None
                return False
        return False

    def receive_empty_pdu(self):
        if BTLE_DATA in self.pkt and self.pkt[BTLE_DATA].len == 0:
            return True
        return False

    def receive_2_empty_pdu(self):
        if BTLE_DATA in self.pkt and self.pkt[BTLE_DATA].len == 0:
            self.empty_pdu_count += 1
            if self.empty_pdu_count >= 3:
                self.empty_pdu_count = 0
                return True
        return False

    def send_feature_request(self):
        self.master_feature_set = 'le_encryption+le_data_len_ext'
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_FEATURE_REQ(
            feature_set=self.master_feature_set)
        # if self.v == 0:
        #     self.v = 1
        # else:
        #     pkt = BTLE('7083329a431908210000000000bfa11891a5'.decode('hex'))
        #     self.v = 0
        self.send(pkt)
        # self.send_encryption_request()
        # self.send_feature_request()

    def send_feature_request_feature_set_zero(self):
        self.master_feature_set = ''
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_FEATURE_REQ(
            feature_set=self.master_feature_set)
        # if self.v == 0:
        #     self.v = 1
        # else:
        #     pkt = BTLE('7083329a431908210000000000bfa11891a5'.decode('hex'))
        #     self.v = 0
        self.send(pkt)
        # self.send_encryption_request()
        # self.send_feature_request()

    def receive_feature_request(self):
        print("Packet Summary: " + self.pkt.summary() + " " + str(self.pkt_received))
        if self.pkt_received:
            if LL_SLAVE_FEATURE_REQ in self.pkt:
                print("I reached in receive_feature_req")
                self.slave_feature_set = self.pkt.feature_set
                print(Fore.GREEN + "[!] Slave features: " + str(self.slave_feature_set))
                return True
        return False

    def send_feature_response(self):
        self.master_feature_set = 'le_encryption+le_data_len_ext'
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_FEATURE_RSP(
            feature_set=self.master_feature_set)

        self.send(pkt)

    def send_feature_response_feature_set_zero(self):
        self.master_feature_set = ''
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_FEATURE_RSP(
            feature_set=self.master_feature_set)

        self.send(pkt)

    def receive_feature_response(self):
        if self.pkt_received:
            if LL_FEATURE_RSP in self.pkt:
                self.slave_feature_set = self.pkt.feature_set
                print(Fore.GREEN + "[!] Slave features: " + str(self.slave_feature_set))
                return True
        return False

    def send_length_request(self):
        # pkt = BTLE('7083329a040914fb00121178f048085987a2'.decode('hex'))
        # self.send(pkt)
        # pkt = BTLE('7083329a030914fb00f9e354af480867ef65'.decode('hex'))
        # self.send(pkt)

        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_REQ(
            max_tx_bytes=self.master_mtu + 4, max_rx_bytes=self.master_mtu + 4)
        # pkt[BTLE_DATA].LLID = 0
        self.send(pkt)
        # self.send_encryption_request()

    def send_length_request_zero_rx_tx(self):
        # pkt = BTLE('7083329a040914fb00121178f048085987a2'.decode('hex'))
        # self.send(pkt)
        # pkt = BTLE('7083329a030914fb00f9e354af480867ef65'.decode('hex'))
        # self.send(pkt)

        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_REQ(
            max_tx_bytes=0, max_rx_bytes=0)
        # pkt[BTLE_DATA].LLID = 0
        self.send(pkt)
        # self.send_encryption_request()

    def send_length_request_zero_time(self):
        # pkt = BTLE('7083329a040914fb00121178f048085987a2'.decode('hex'))
        # self.send(pkt)
        # pkt = BTLE('7083329a030914fb00f9e354af480867ef65'.decode('hex'))
        # self.send(pkt)

        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_REQ(
            max_tx_bytes=self.master_mtu + 4, max_rx_bytes=self.master_mtu + 4, max_rx_time = 0, max_tx_time = 0 )
        # pkt[BTLE_DATA].LLID = 0
        self.send(pkt)
        # self.send_encryption_request()

    def receive_length_request(self):
        if self.pkt_received:
            if LL_LENGTH_REQ in self.pkt:
                return True
        return False

    def send_length_response(self):
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_RSP(
            max_tx_bytes=self.att.mtu + 4, max_rx_bytes=self.att.mtu + 4)
        # pkt.len = 10  # Crash fitbit/Cypress fastly
        # self.send_encryption_request()
        self.send(pkt)

    def send_length_response_zero_rx_tx(self):
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_RSP(
            max_tx_bytes=0, max_rx_bytes=0)
        # pkt.len = 10  # Crash fitbit/Cypress fastly
        # self.send_encryption_request()
        self.send(pkt)
    
    def send_length_response_zero_time(self):
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_LENGTH_RSP(
            max_tx_bytes=self.att.mtu + 4, max_rx_bytes=self.att.mtu + 4, max_rx_time=0, max_tx_time=0)
        # pkt.len = 10  # Crash fitbit/Cypress fastly
        # self.send_encryption_request()
        self.send(pkt)

    def receive_length_response(self):
        if LL_UNKNOWN_RSP in self.pkt:
            return True
        if LL_LENGTH_RSP in self.pkt:
            return True

        return False

    def send_version_indication(self):
        # Using BLE version 4.2
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_VERSION_IND(version='4.2')
        # pkt.LLID = 0
        # pkt.len = 240  # Crash fitbit/Cypress fastly
        # pkt.len = 10  # Crash fitbit/Cypress fastly
        self.send(pkt)
        # self.send_encryption_request()

    def send_version_indication_llid_zero(self):
        # Using BLE version 4.2
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_VERSION_IND(version='4.2')
        pkt.LLID = 0
        # pkt.len = 240  # Crash fitbit/Cypress fastly
        # pkt.len = 10  # Crash fitbit/Cypress fastly
        self.send(pkt)
        # self.send_encryption_request()

    def send_version_indication_max_len(self):
        # Using BLE version 4.2
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_VERSION_IND(version='4.2')
        # pkt.LLID = 0
        pkt.len = 240  # Crash fitbit/Cypress fastly
        # pkt.len = 10  # Crash fitbit/Cypress fastly
        self.send(pkt)
        # self.send_encryption_request()

    def receive_version_indication(self):

        if self.pkt_received:
            #if LL_SLAVE_FEATURE_REQ in self.pkt:
                #self.send_feature_response()

            if LL_VERSION_IND in self.pkt:
                self.slave_ble_version = self.pkt[LL_VERSION_IND].version

                if BTLE_Versions.has_key(self.slave_ble_version):
                    print(Fore.GREEN + "[!] Slave BLE Version: " + str(
                        BTLE_Versions[self.slave_ble_version]) + " - " + hex(self.slave_ble_version))
                else:
                    print(Fore.RED + "[!] Unknown Slave BLE Version: " + hex(self.slave_ble_version))
                self.version_received = True
                return True
        return False

    def receive_security_request(self):
        if SM_Security_Request in self.pkt:
            # self.paring_auth_request = self.pkt[SM_Security_Request].authentication
            # self.pairing_iocap = 0x04  # Change device to Keyboard an Display
            # self.send_encryption_request()
            # self.send_feature_request()
            return True

    def send_security_request(self):
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / \
              SM_Security_Request(authentication=self.paring_auth_request)
        self.send(pkt)

    def send_mtu_length_request(self):
        # self.raw_att(ATT_Exchange_MTU_Response(self.att.mtu), None, None)
        pkt = BTLE(access_addr=self.conn_access_address) / \
              BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Exchange_MTU_Request(mtu=self.att.mtu)
        # pkt.len = 186
        # pkt[BTLE_DATA].LLID = 0  # Fitbit deadlock

        self.send(pkt)
        # self.send(pkt)

    def send_mtu_length_request_llid_zero(self):
        # self.raw_att(ATT_Exchange_MTU_Response(self.att.mtu), None, None)
        pkt = BTLE(access_addr=self.conn_access_address) / \
              BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Exchange_MTU_Request(mtu=self.att.mtu)
        # pkt.len = 186
        pkt[BTLE_DATA].LLID = 0  # Fitbit deadlock

        self.send(pkt)
        # self.send(pkt)

    def send_mtu_length_request_mtu_zero(self):
        # self.raw_att(ATT_Exchange_MTU_Response(self.att.mtu), None, None)
        pkt = BTLE(access_addr=self.conn_access_address) / \
              BTLE_DATA() / L2CAP_Hdr() / ATT_Hdr() / ATT_Exchange_MTU_Request(mtu=0)
        # pkt.len = 186
        # pkt[BTLE_DATA].LLID = 0  # Fitbit deadlock

        self.send(pkt)
        # self.send(pkt)

    def receive_mtu_length_request(self):
        if self.pkt_received:
            if ATT_Exchange_MTU_Request in self.pkt:
                # self.att.set_mtu(self.pkt.mtu)
                return True
        return False


    def send_mtu_length_response(self):
        print("sending mtu length response before!")
        if self.pkt is None or saved_pkt_with_ATT_Hdr is None:
            return
        #if ATT_Hdr in self.pkt:
            #print("sending mtu length response  with self pkt header!")
            #self.att.marshall_request(None, self.pkt[ATT_Hdr], self.peer_address)
        #elif ATT_Hdr in saved_pkt_with_ATT_Hdr:
            #print("sending mtu length response with saved pkt header")
            #self.att.marshall_request(None, saved_pkt_with_ATT_Hdr[ATT_Hdr], self.peer_address)
        #else:
            #print("Do nothing in mtu_length_response")

    def send_mtu_length_response_llid_zero(self):
        print("sending mtu length response before!")
        if self.pkt is None or saved_pkt_with_ATT_Hdr is None:
            return
        if ATT_Hdr in self.pkt and self.pkt[BTLE_DATA] is not None and self.pkt[BTLE_DATA].LLID is not None:
            print("sending mtu length response  with self pkt header!")
            self.pkt[BTLE_DATA].LLID = 0
            self.att.marshall_request(None, self.pkt[ATT_Hdr], self.peer_address)
        elif ATT_Hdr in saved_pkt_with_ATT_Hdr and saved_pkt_with_ATT_Hdr[BTLE_DATA] is not None and saved_pkt_with_ATT_Hdr[BTLE_DATA].LLID is not None:
            print("sending mtu length response with saved pkt header")
            saved_pkt_with_ATT_Hdr[BTLE_DATA].LLID = 0
            self.att.marshall_request(None, saved_pkt_with_ATT_Hdr[ATT_Hdr], self.peer_address)
        else:
            print("Do nothing in send_mtu_length_response_llid_zero")

    def send_mtu_length_response_mtu_zero(self):
        print("sending mtu length response before!")
        if self.pkt is None or saved_pkt_with_ATT_Hdr is None:
            return
        if ATT_Hdr in self.pkt and self.pkt[ATT_Exchange_MTU_Request] is not None and self.pkt[ATT_Exchange_MTU_Request].mtu is not None:
            print("sending mtu length response  with self pkt header!")
            self.pkt[BTLE_DATA].mtu = 0
            self.att.marshall_request(None, self.pkt[ATT_Hdr], self.peer_address)
        elif ATT_Hdr in saved_pkt_with_ATT_Hdr and saved_pkt_with_ATT_Hdr[ATT_Exchange_MTU_Request] is not None and saved_pkt_with_ATT_Hdr[ATT_Exchange_MTU_Request].mtu is not None:
            print("sending mtu length response with saved pkt header")
            saved_pkt_with_ATT_Hdr[BTLE_DATA].mtu = 0
            self.att.marshall_request(None, saved_pkt_with_ATT_Hdr[ATT_Hdr], self.peer_address)
        else:
            print("Do nothing in send_mtu_length_response_mtu_zero")

    def receive_mtu_length_response(self):
        if LL_LENGTH_REQ in self.pkt:
            # TODO: Handle 2cap fragmentation if length is less than mtu
            # By responding to length request from slave here, length will be registered by slave
            self.send_length_response()
        if ATT_Exchange_MTU_Response in self.pkt:
            self.att.set_mtu(self.pkt.mtu)
            return True


    def send_pair_request_keyboard_display(self):
        # paring_auth_request = 0x00  # No bonding
        # paring_auth_request = 0x01  # Bonding
        # paring_auth_request = 0x08 | 0x01  # Le Secure Connection + bonding
        # paring_auth_request = 0x04 | 0x01  # MITM + bonding
        self.paring_auth_request = 0x08 | 0x40 | 0x01  # Le Secure Connection + MITM + bonding
        self.pairing_iocap = 0x04
        # pkt = BTLE('7083329a020b07000600e6030009100707699784'.decode('hex'))
        # self.send(pkt)
        # self.send_version_indication()
        # pkt = BTLE('7083329a00060c0800000000a7b884'.decode('hex'))
        # self.send(pkt)
        # pkt = BTLE('7083329a020b07000600c9030009100707e829fb'.decode('hex'))
        # self.send(pkt)
        # pkt[BTLE_DATA].MD = True
        # self.send(pkt)
        # return

        if not self.pairing_starting:
            BLESMPServer.configure_connection(self.master_address_raw, self.slave_address_raw,
                                              self.slave_address_type,
                                              self.pairing_iocap, self.paring_auth_request)
            hci_res = BLESMPServer.pairing_request()
            if hci_res:
                pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]
                # pkt = BTLE('7083329a03720700060001e90009d907077dbdc6'.decode('hex'))  # Crash Cypress (3.61 BLE) / NXP
                # pkt = BTLE('7083329a06ba070006000c03f5fa100fbbcfb5a6'.decode('hex'))  # Crash DA14680-01 xiaomi
                #pkt[SM_Pairing_Request].authentication &= 0xF7  # Clear secure connections flag
                # pkt[SM_Pairing_Request].authentication &= 0xF6  # Clear secure connections flag + bonding
                # pkt.LLID = 0
                # pkt.len = 186
                # pkt[SM_Pairing_Request].max_key_size = 253  # Crash Telink
                # pkt = BTLE('7083329a020b0700060001d98e0143f3fe0d80b8'.decode('hex'))
                # pkt = BTLE('7083329a020b07000600017a0054fd4e9287c7dc'.decode('hex'))  # Telink crash pre step
                # pkt = BTLE('7083329a0201070006000103000910070787b87c'.decode('hex'))  # Microchip crash
                # ------------
                # pkt = BTLE('7083329ae015110006008d2a1085d12b5f0dab481c430e6f329bc5c31ee4'.decode('hex'))  # PSoC 6 crash
                # self.send(pkt)
                # self.disable_timeout('conn_supervision_timer')
                # self.disable_timeout('conn_general_timer')
                # self.reset_vars()
                # self.machine.reset_machine()
                # ------------
                # pkt[BTLE_DATA].len = 2pairing_request
                # pkt = BTLE('7083329a020b07000600010300ac1007d637ab16'.decode('hex'))  # Crash NRF51422
                # pkt = BTLE('7083329a020b070006000103004910070790707f'.decode('hex'))  # Crash NRF51422
                # pkt = BTLE('7083329a620b0700060001030049100707d02467'.decode('hex'))  # Crash NRF51422
                # self.send(pkt)
                #pkt[SM_Pairing_Request].oob = 1
                print("Pairing Request packet")
                pkt.show()
                self.send(pkt)
                # self.send(pkt)
                # self.send_encryption_request()
                # self.v = 0
        else:
            self.send(self.sent_packet)

    def send_pair_request_display_yes_no(self):
        # paring_auth_request = 0x00  # No bonding
        # paring_auth_request = 0x01  # Bonding
        # paring_auth_request = 0x08 | 0x01  # Le Secure Connection + bonding
        # paring_auth_request = 0x04 | 0x01  # MITM + bonding
        self.paring_auth_request = 0x08 | 0x40 | 0x01  # Le Secure Connection + MITM + bonding
        self.pairing_iocap = 0x01
        # pkt = BTLE('7083329a020b07000600e6030009100707699784'.decode('hex'))
        # self.send(pkt)
        # self.send_version_indication()
        # pkt = BTLE('7083329a00060c0800000000a7b884'.decode('hex'))
        # self.send(pkt)
        # pkt = BTLE('7083329a020b07000600c9030009100707e829fb'.decode('hex'))
        # self.send(pkt)
        # pkt[BTLE_DATA].MD = True
        # self.send(pkt)
        # return

        if not self.pairing_starting:
            BLESMPServer.configure_connection(self.master_address_raw, self.slave_address_raw,
                                              self.slave_address_type,
                                              self.pairing_iocap, self.paring_auth_request)
            hci_res = BLESMPServer.pairing_request()
            if hci_res:
                pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]
                # pkt = BTLE('7083329a03720700060001e90009d907077dbdc6'.decode('hex'))  # Crash Cypress (3.61 BLE) / NXP
                # pkt = BTLE('7083329a06ba070006000c03f5fa100fbbcfb5a6'.decode('hex'))  # Crash DA14680-01 xiaomi
                #pkt[SM_Pairing_Request].authentication &= 0xF7  # Clear secure connections flag
                # pkt[SM_Pairing_Request].authentication &= 0xF6  # Clear secure connections flag + bonding
                # pkt.LLID = 0
                # pkt.len = 186
                # pkt[SM_Pairing_Request].max_key_size = 253  # Crash Telink
                # pkt = BTLE('7083329a020b0700060001d98e0143f3fe0d80b8'.decode('hex'))
                # pkt = BTLE('7083329a020b07000600017a0054fd4e9287c7dc'.decode('hex'))  # Telink crash pre step
                # pkt = BTLE('7083329a0201070006000103000910070787b87c'.decode('hex'))  # Microchip crash
                # ------------
                # pkt = BTLE('7083329ae015110006008d2a1085d12b5f0dab481c430e6f329bc5c31ee4'.decode('hex'))  # PSoC 6 crash
                # self.send(pkt)
                # self.disable_timeout('conn_supervision_timer')
                # self.disable_timeout('conn_general_timer')
                # self.reset_vars()
                # self.machine.reset_machine()
                # ------------
                # pkt[BTLE_DATA].len = 2pairing_request
                # pkt = BTLE('7083329a020b07000600010300ac1007d637ab16'.decode('hex'))  # Crash NRF51422
                # pkt = BTLE('7083329a020b070006000103004910070790707f'.decode('hex'))  # Crash NRF51422
                # pkt = BTLE('7083329a620b0700060001030049100707d02467'.decode('hex'))  # Crash NRF51422
                # self.send(pkt)
                #pkt[SM_Pairing_Request].oob = 1
                print("Pairing Request packet")
                pkt.show()
                self.send(pkt)
                # self.send(pkt)
                # self.send_encryption_request()
                # self.v = 0
        else:
            self.send(self.sent_packet)


    def send_pair_request(self):
        # paring_auth_request = 0x00  # No bonding
        # paring_auth_request = 0x01  # Bonding
        # paring_auth_request = 0x08 | 0x01  # Le Secure Connection + bonding
        # paring_auth_request = 0x04 | 0x01  # MITM + bonding
        self.paring_auth_request = 0x08 | 0x40 | 0x01  # Le Secure Connection + MITM + bonding
        self.pairing_iocap = 0x03
        # pkt = BTLE('7083329a020b07000600e6030009100707699784'.decode('hex'))
        # self.send(pkt)
        # self.send_version_indication()
        # pkt = BTLE('7083329a00060c0800000000a7b884'.decode('hex'))
        # self.send(pkt)
        # pkt = BTLE('7083329a020b07000600c9030009100707e829fb'.decode('hex'))
        # self.send(pkt)
        # pkt[BTLE_DATA].MD = True
        # self.send(pkt)
        # return

        if not self.pairing_starting:
            BLESMPServer.configure_connection(self.master_address_raw, self.slave_address_raw,
                                              self.slave_address_type,
                                              self.pairing_iocap, self.paring_auth_request)
            hci_res = BLESMPServer.pairing_request()
            if hci_res:
                pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]
                # pkt = BTLE('7083329a03720700060001e90009d907077dbdc6'.decode('hex'))  # Crash Cypress (3.61 BLE) / NXP
                # pkt = BTLE('7083329a06ba070006000c03f5fa100fbbcfb5a6'.decode('hex'))  # Crash DA14680-01 xiaomi
                #pkt[SM_Pairing_Request].authentication &= 0xF7  # Clear secure connections flag
                # pkt[SM_Pairing_Request].authentication &= 0xF6  # Clear secure connections flag + bonding
                # pkt.LLID = 0
                # pkt.len = 186
                # pkt[SM_Pairing_Request].max_key_size = 253  # Crash Telink
                # pkt = BTLE('7083329a020b0700060001d98e0143f3fe0d80b8'.decode('hex'))
                # pkt = BTLE('7083329a020b07000600017a0054fd4e9287c7dc'.decode('hex'))  # Telink crash pre step
                # pkt = BTLE('7083329a0201070006000103000910070787b87c'.decode('hex'))  # Microchip crash
                # ------------
                # pkt = BTLE('7083329ae015110006008d2a1085d12b5f0dab481c430e6f329bc5c31ee4'.decode('hex'))  # PSoC 6 crash
                # self.send(pkt)
                # self.disable_timeout('conn_supervision_timer')
                # self.disable_timeout('conn_general_timer')
                # self.reset_vars()
                # self.machine.reset_machine()
                # ------------
                # pkt[BTLE_DATA].len = 2pairing_request
                # pkt = BTLE('7083329a020b07000600010300ac1007d637ab16'.decode('hex'))  # Crash NRF51422
                # pkt = BTLE('7083329a020b070006000103004910070790707f'.decode('hex'))  # Crash NRF51422
                # pkt = BTLE('7083329a620b0700060001030049100707d02467'.decode('hex'))  # Crash NRF51422
                # self.send(pkt)
                #pkt[SM_Pairing_Request].oob = 1
                print("Pairing Request packet")
                pkt.show()
                self.send(pkt)
                # self.send(pkt)
                # self.send_encryption_request()
                # self.v = 0
        else:
            self.send(self.sent_packet)

    def send_pair_request_oob(self):
        # paring_auth_request = 0x00  # No bonding
        # paring_auth_request = 0x01  # Bonding
        # paring_auth_request = 0x08 | 0x01  # Le Secure Connection + bonding
        # paring_auth_request = 0x04 | 0x01  # MITM + bonding
        self.paring_auth_request = 0x08 | 0x40 | 0x01  # Le Secure Connection + MITM + bonding
        self.pairing_iocap = 0x03
        #self.paring_auth_request = 0x40 | 0x01  # Le Secure Connection + MITM + bonding
        # pkt = BTLE('7083329a020b07000600e6030009100707699784'.decode('hex'))
        # self.send(pkt)
        # self.send_version_indication()
        # pkt = BTLE('7083329a00060c0800000000a7b884'.decode('hex'))
        # self.send(pkt)
        # pkt = BTLE('7083329a020b07000600c9030009100707e829fb'.decode('hex'))
        # self.send(pkt)
        # pkt[BTLE_DATA].MD = True
        # self.send(pkt)
        # return

        if not self.pairing_starting:
            BLESMPServer.configure_connection(self.master_address_raw, self.slave_address_raw,
                                              self.slave_address_type,
                                              self.pairing_iocap, self.paring_auth_request)
            hci_res = BLESMPServer.pairing_request()
            if hci_res:
                pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]
                # pkt = BTLE('7083329a03720700060001e90009d907077dbdc6'.decode('hex'))  # Crash Cypress (3.61 BLE) / NXP
                # pkt = BTLE('7083329a06ba070006000c03f5fa100fbbcfb5a6'.decode('hex'))  # Crash DA14680-01 xiaomi
                #pkt[SM_Pairing_Request].authentication = 0x08 | 0x40 | 0x01   # Clear secure connections flag
                pkt[SM_Pairing_Request].oob = 1
                # pkt.LLID = 0
                # pkt.len = 186
                # pkt[SM_Pairing_Request].max_key_size = 253  # Crash Telink
                # pkt = BTLE('7083329a020b0700060001d98e0143f3fe0d80b8'.decode('hex'))
                # pkt = BTLE('7083329a020b07000600017a0054fd4e9287c7dc'.decode('hex'))  # Telink crash pre step
                # pkt = BTLE('7083329a0201070006000103000910070787b87c'.decode('hex'))  # Microchip crash
                # ------------
                # pkt = BTLE('7083329ae015110006008d2a1085d12b5f0dab481c430e6f329bc5c31ee4'.decode('hex'))  # PSoC 6 crash
                # self.send(pkt)
                # self.disable_timeout('conn_supervision_timer')
                # self.disable_timeout('conn_general_timer')
                # self.reset_vars()
                # self.machine.reset_machine()
                # ------------
                # pkt[BTLE_DATA].len = 2pairing_request
                # pkt = BTLE('7083329a020b07000600010300ac1007d637ab16'.decode('hex'))  # Crash NRF51422
                # pkt = BTLE('7083329a020b070006000103004910070790707f'.decode('hex'))  # Crash NRF51422
                # pkt = BTLE('7083329a620b0700060001030049100707d02467'.decode('hex'))  # Crash NRF51422
                # self.send(pkt)
                # pkt[SM_Pairing_Request].oob = 1
                print("Pairing Request packet")
                pkt.show()
                self.send(pkt)
                # self.send(pkt)
                # self.send_encryption_request()
                # self.v = 0
        else:
            self.send(self.sent_packet)

    def send_pair_request_key_zero(self):
        # paring_auth_request = 0x00  # No bonding
        # paring_auth_request = 0x01  # Bonding
        # paring_auth_request = 0x08 | 0x01  # Le Secure Connection + bonding
        # paring_auth_request = 0x04 | 0x01  # MITM + bonding
        #self.paring_auth_request = 0x08 | 0x40 | 0x01  # Le Secure Connection + MITM + bonding
        self.paring_auth_request = 0x0d
        self.pairing_iocap = 0x03
        # pkt = BTLE('7083329a020b07000600e6030009100707699784'.decode('hex'))
        # self.send(pkt)
        # self.send_version_indication()
        # pkt = BTLE('7083329a00060c0800000000a7b884'.decode('hex'))
        # self.send(pkt)
        # pkt = BTLE('7083329a020b07000600c9030009100707e829fb'.decode('hex'))
        # self.send(pkt)
        # pkt[BTLE_DATA].MD = True
        # self.send(pkt)
        # return

        if not self.pairing_starting:
            BLESMPServer.configure_connection(self.master_address_raw, self.slave_address_raw,
                                              self.slave_address_type,
                                              self.pairing_iocap, self.paring_auth_request)
            hci_res = BLESMPServer.pairing_request()
            if hci_res:
                pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]
                print(str(pkt.command()))
                if SM_Pairing_Request in pkt:
                    # pkt = BTLE('7083329a03720700060001e90009d907077dbdc6'.decode('hex'))  # Crash Cypress (3.61 BLE) / NXP
                    # pkt = BTLE('7083329a06ba070006000c03f5fa100fbbcfb5a6'.decode('hex'))  # Crash DA14680-01 xiaomi
                    #pkt[SM_Pairing_Request].authentication &= 0xF7  # Clear secure connections flag
                    # pkt[SM_Pairing_Request].authentication &= 0xF6  # Clear secure connections flag + bonding
                    # pkt.LLID = 0
                    # pkt.len = 186

                    pkt[SM_Pairing_Request].max_key_size = 0xff  # Crash Telink
                    # pkt = BTLE('7083329a020b0700060001d98e0143f3fe0d80b8'.decode('hex'))
                    # pkt = BTLE('7083329a020b07000600017a0054fd4e9287c7dc'.decode('hex'))  # Telink crash pre step
                    # pkt = BTLE('7083329a0201070006000103000910070787b87c'.decode('hex'))  # Microchip crash
                    # ------------
                    # pkt = BTLE('7083329ae015110006008d2a1085d12b5f0dab481c430e6f329bc5c31ee4'.decode('hex'))  # PSoC 6 crash
                    # self.send(pkt)
                    # self.disable_timeout('conn_supervision_timer')
                    # self.disable_timeout('conn_general_timer')
                    # self.reset_vars()
                    # self.machine.reset_machine()
                    # ------------
                    # pkt[BTLE_DATA].len = 2pairing_request
                    # pkt = BTLE('7083329a020b07000600010300ac1007d637ab16'.decode('hex'))  # Crash NRF51422
                    # pkt = BTLE('7083329a020b070006000103004910070790707f'.decode('hex'))  # Crash NRF51422
                    # pkt = BTLE('7083329a620b0700060001030049100707d02467'.decode('hex'))  # Crash NRF51422
                    # self.send(pkt)
                    # pkt[SM_Pairing_Request].oob = 1
                    print("Pairing Request packet")
                    pkt.show()
                    self.send(pkt)
                    # self.send(pkt)
                    # self.send_encryption_request()
                    # self.v = 0
        else:
            self.send(self.sent_packet)


    def send_pair_request_no_sc(self):
        # paring_auth_request = 0x00  # No bonding
        # paring_auth_request = 0x01  # Bonding
        # paring_auth_request = 0x08 | 0x01  # Le Secure Connection + bonding
        self.paring_auth_request = 0x04 | 0x01  # MITM + bonding
        self.pairing_iocap = 0x03
        #paring_auth_request = 0x08 | 0x40 | 0x01  # Le Secure Connection + MITM + bonding
        # pkt = BTLE('7083329a020b07000600e6030009100707699784'.decode('hex'))
        # self.send(pkt)
        # self.send_version_indication()
        # pkt = BTLE('7083329a00060c0800000000a7b884'.decode('hex'))
        # self.send(pkt)
        # pkt = BTLE('7083329a020b07000600c9030009100707e829fb'.decode('hex'))
        # self.send(pkt)
        # pkt[BTLE_DATA].MD = True
        # self.send(pkt)
        # return

        if not self.pairing_starting:
            BLESMPServer.configure_connection(self.master_address_raw, self.slave_address_raw,
                                              self.slave_address_type,
                                              self.pairing_iocap, self.paring_auth_request)
            hci_res = BLESMPServer.pairing_request()
            if hci_res:
                pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]
                # pkt = BTLE('7083329a03720700060001e90009d907077dbdc6'.decode('hex'))  # Crash Cypress (3.61 BLE) / NXP
                # pkt = BTLE('7083329a06ba070006000c03f5fa100fbbcfb5a6'.decode('hex'))  # Crash DA14680-01 xiaomi
                if SM_Pairing_Request in pkt:
                    #pkt[SM_Pairing_Request].authentication = 0x08 | 0x40 | 0x01
                    pkt[SM_Pairing_Request].authentication &= 0xF7  # Clear secure connections flag
                    # pkt.LLID = 0
                    # pkt.len = 186
                    # pkt[SM_Pairing_Request].max_key_size = 253  # Crash Telink
                    # pkt = BTLE('7083329a020b0700060001d98e0143f3fe0d80b8'.decode('hex'))
                    # pkt = BTLE('7083329a020b07000600017a0054fd4e9287c7dc'.decode('hex'))  # Telink crash pre step
                    # pkt = BTLE('7083329a0201070006000103000910070787b87c'.decode('hex'))  # Microchip crash
                    # ------------
                    # pkt = BTLE('7083329ae015110006008d2a1085d12b5f0dab481c430e6f329bc5c31ee4'.decode('hex'))  # PSoC 6 crash
                    # self.send(pkt)
                    # self.disable_timeout('conn_supervision_timer')
                    # self.disable_timeout('conn_general_timer')
                    # self.reset_vars()
                    # self.machine.reset_machine()
                    # ------------
                    # pkt[BTLE_DATA].len = 2pairing_request
                    # pkt = BTLE('7083329a020b07000600010300ac1007d637ab16'.decode('hex'))  # Crash NRF51422
                    # pkt = BTLE('7083329a020b070006000103004910070790707f'.decode('hex'))  # Crash NRF51422
                    # pkt = BTLE('7083329a620b0700060001030049100707d02467'.decode('hex'))  # Crash NRF51422
                    # self.send(pkt)
                    # pkt[SM_Pairing_Request].oob = 1
                    print("Pairing Request packet")
                    pkt.show()
                    self.send(pkt)
                    # self.send(pkt)
                    # self.send_encryption_request()
                    # self.v = 0
        else:
            self.send(self.sent_packet)


    def send_pair_request_no_sc_keyboard_display(self):
        # paring_auth_request = 0x00  # No bonding
        # paring_auth_request = 0x01  # Bonding
        # paring_auth_request = 0x08 | 0x01  # Le Secure Connection + bonding
        self.paring_auth_request = 0x04 | 0x01  # MITM + bonding
        self.pairing_iocap = 0x04
        #paring_auth_request = 0x08 | 0x40 | 0x01  # Le Secure Connection + MITM + bonding
        # pkt = BTLE('7083329a020b07000600e6030009100707699784'.decode('hex'))
        # self.send(pkt)
        # self.send_version_indication()
        # pkt = BTLE('7083329a00060c0800000000a7b884'.decode('hex'))
        # self.send(pkt)
        # pkt = BTLE('7083329a020b07000600c9030009100707e829fb'.decode('hex'))
        # self.send(pkt)
        # pkt[BTLE_DATA].MD = True
        # self.send(pkt)
        # return

        if not self.pairing_starting:
            BLESMPServer.configure_connection(self.master_address_raw, self.slave_address_raw,
                                              self.slave_address_type,
                                              self.pairing_iocap, self.paring_auth_request)
            hci_res = BLESMPServer.pairing_request()
            if hci_res:
                pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]
                # pkt = BTLE('7083329a03720700060001e90009d907077dbdc6'.decode('hex'))  # Crash Cypress (3.61 BLE) / NXP
                # pkt = BTLE('7083329a06ba070006000c03f5fa100fbbcfb5a6'.decode('hex'))  # Crash DA14680-01 xiaomi
                if SM_Pairing_Request in pkt:
                    #pkt[SM_Pairing_Request].authentication = 0x08 | 0x40 | 0x01
                    pkt[SM_Pairing_Request].authentication &= 0xF7  # Clear secure connections flag
                    # pkt.LLID = 0
                    # pkt.len = 186
                    # pkt[SM_Pairing_Request].max_key_size = 253  # Crash Telink
                    # pkt = BTLE('7083329a020b0700060001d98e0143f3fe0d80b8'.decode('hex'))
                    # pkt = BTLE('7083329a020b07000600017a0054fd4e9287c7dc'.decode('hex'))  # Telink crash pre step
                    # pkt = BTLE('7083329a0201070006000103000910070787b87c'.decode('hex'))  # Microchip crash
                    # ------------
                    # pkt = BTLE('7083329ae015110006008d2a1085d12b5f0dab481c430e6f329bc5c31ee4'.decode('hex'))  # PSoC 6 crash
                    # self.send(pkt)
                    # self.disable_timeout('conn_supervision_timer')
                    # self.disable_timeout('conn_general_timer')
                    # self.reset_vars()
                    # self.machine.reset_machine()
                    # ------------
                    # pkt[BTLE_DATA].len = 2pairing_request
                    # pkt = BTLE('7083329a020b07000600010300ac1007d637ab16'.decode('hex'))  # Crash NRF51422
                    # pkt = BTLE('7083329a020b070006000103004910070790707f'.decode('hex'))  # Crash NRF51422
                    # pkt = BTLE('7083329a620b0700060001030049100707d02467'.decode('hex'))  # Crash NRF51422
                    # self.send(pkt)
                    # pkt[SM_Pairing_Request].oob = 1
                    print("Pairing Request packet")
                    pkt.show()
                    self.send(pkt)
                    # self.send(pkt)
                    # self.send_encryption_request()
                    # self.v = 0
        else:
            self.send(self.sent_packet)




    def send_pair_request_no_sc_display_yes_no(self):
        # paring_auth_request = 0x00  # No bonding
        # paring_auth_request = 0x01  # Bonding
        # paring_auth_request = 0x08 | 0x01  # Le Secure Connection + bonding
        self.paring_auth_request = 0x04 | 0x01  # MITM + bonding
        self.pairing_iocap = 0x01
        #paring_auth_request = 0x08 | 0x40 | 0x01  # Le Secure Connection + MITM + bonding
        # pkt = BTLE('7083329a020b07000600e6030009100707699784'.decode('hex'))
        # self.send(pkt)
        # self.send_version_indication()
        # pkt = BTLE('7083329a00060c0800000000a7b884'.decode('hex'))
        # self.send(pkt)
        # pkt = BTLE('7083329a020b07000600c9030009100707e829fb'.decode('hex'))
        # self.send(pkt)
        # pkt[BTLE_DATA].MD = True
        # self.send(pkt)
        # return

        if not self.pairing_starting:
            BLESMPServer.configure_connection(self.master_address_raw, self.slave_address_raw,
                                              self.slave_address_type,
                                              self.pairing_iocap, self.paring_auth_request)
            hci_res = BLESMPServer.pairing_request()
            if hci_res:
                pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]
                # pkt = BTLE('7083329a03720700060001e90009d907077dbdc6'.decode('hex'))  # Crash Cypress (3.61 BLE) / NXP
                # pkt = BTLE('7083329a06ba070006000c03f5fa100fbbcfb5a6'.decode('hex'))  # Crash DA14680-01 xiaomi
                if SM_Pairing_Request in pkt:
                    #pkt[SM_Pairing_Request].authentication = 0x08 | 0x40 | 0x01
                    pkt[SM_Pairing_Request].authentication &= 0xF7  # Clear secure connections flag
                    # pkt.LLID = 0
                    # pkt.len = 186
                    # pkt[SM_Pairing_Request].max_key_size = 253  # Crash Telink
                    # pkt = BTLE('7083329a020b0700060001d98e0143f3fe0d80b8'.decode('hex'))
                    # pkt = BTLE('7083329a020b07000600017a0054fd4e9287c7dc'.decode('hex'))  # Telink crash pre step
                    # pkt = BTLE('7083329a0201070006000103000910070787b87c'.decode('hex'))  # Microchip crash
                    # ------------
                    # pkt = BTLE('7083329ae015110006008d2a1085d12b5f0dab481c430e6f329bc5c31ee4'.decode('hex'))  # PSoC 6 crash
                    # self.send(pkt)
                    # self.disable_timeout('conn_supervision_timer')
                    # self.disable_timeout('conn_general_timer')
                    # self.reset_vars()
                    # self.machine.reset_machine()
                    # ------------
                    # pkt[BTLE_DATA].len = 2pairing_request
                    # pkt = BTLE('7083329a020b07000600010300ac1007d637ab16'.decode('hex'))  # Crash NRF51422
                    # pkt = BTLE('7083329a020b070006000103004910070790707f'.decode('hex'))  # Crash NRF51422
                    # pkt = BTLE('7083329a620b0700060001030049100707d02467'.decode('hex'))  # Crash NRF51422
                    # self.send(pkt)
                    # pkt[SM_Pairing_Request].oob = 1
                    print("Pairing Request packet")
                    pkt.show()
                    self.send(pkt)
                    # self.send(pkt)
                    # self.send_encryption_request()
                    # self.v = 0
        else:
            self.send(self.sent_packet)
    def send_pair_request_no_sc_bonding(self):

        # pkt = BTLE('7083329a020b07000600e6030009100707699784'.decode('hex'))
        # self.send(pkt)
        # self.send_version_indication()
        # pkt = BTLE('7083329a00060c0800000000a7b884'.decode('hex'))
        # self.send(pkt)
        # pkt = BTLE('7083329a020b07000600c9030009100707e829fb'.decode('hex'))
        # self.send(pkt)
        # pkt[BTLE_DATA].MD = True
        # self.send(pkt)
        # return

        if not self.pairing_starting:
            BLESMPServer.configure_connection(self.master_address_raw, self.slave_address_raw,
                                              self.slave_address_type,
                                              self.pairing_iocap, self.paring_auth_request)
            hci_res = BLESMPServer.pairing_request()
            if hci_res:
                pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]
                # pkt = BTLE('7083329a03720700060001e90009d907077dbdc6'.decode('hex'))  # Crash Cypress (3.61 BLE) / NXP
                # pkt = BTLE('7083329a06ba070006000c03f5fa100fbbcfb5a6'.decode('hex'))  # Crash DA14680-01 xiaomi
                #pkt[SM_Pairing_Request].authentication &= 0xF7  # Clear secure connections flag

                if SM_Pairing_Request in pkt:
                    pkt[SM_Pairing_Request].authentication &= 0xF6  # Clear secure connections flag + bonding
                    # pkt.LLID = 0
                    # pkt.len = 186
                    # pkt[SM_Pairing_Request].max_key_size = 253  # Crash Telink
                    # pkt = BTLE('7083329a020b0700060001d98e0143f3fe0d80b8'.decode('hex'))
                    # pkt = BTLE('7083329a020b07000600017a0054fd4e9287c7dc'.decode('hex'))  # Telink crash pre step
                    # pkt = BTLE('7083329a0201070006000103000910070787b87c'.decode('hex'))  # Microchip crash
                    # ------------
                    # pkt = BTLE('7083329ae015110006008d2a1085d12b5f0dab481c430e6f329bc5c31ee4'.decode('hex'))  # PSoC 6 crash
                    # self.send(pkt)
                    # self.disable_timeout('conn_supervision_timer')
                    # self.disable_timeout('conn_general_timer')
                    # self.reset_vars()
                    # self.machine.reset_machine()
                    # ------------
                    # pkt[BTLE_DATA].len = 2pairing_request
                    # pkt = BTLE('7083329a020b07000600010300ac1007d637ab16'.decode('hex'))  # Crash NRF51422
                    # pkt = BTLE('7083329a020b070006000103004910070790707f'.decode('hex'))  # Crash NRF51422
                    # pkt = BTLE('7083329a620b0700060001030049100707d02467'.decode('hex'))  # Crash NRF51422
                    # self.send(pkt)
                    # pkt[SM_Pairing_Request].oob = 1
                    print("Pairing Request packet")
                    pkt.show()
                    self.send(pkt)
                    # self.send(pkt)
                    # self.send_encryption_request()
                    # self.v = 0
        else:
            self.send(self.sent_packet)



    def finish_pair_response(self):

        # if SM_Public_Key in self.pkt:
        #     pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Confirm()
        #     self.send(pkt)
        #     pass
        print("In finish_pair_response")
        
        # handling error in ble_central
        if self.pkt is None:
            return

        if SM_Hdr in self.pkt:
            self.pkt.show()
            #
            # if SM_Pairing_Response in self.pkt:  # Telink final crash step
            # self.send_encryption_request()
            # self.conn_ltk = '\xFF' * 16
            # self.conn_ltk = '35A54250A0FC76CDC2893054B4096009'.decode('hex')
            # return True

            # if SM_Confirm in self.pkt:
            #     # pkt = BTLE('7083329a0215110006000700000400000000000000000000000000e94bf0'.decode('hex'))
            #     # self.send(pkt)
            #     self.conn_ltk = '\x00' * 16
            #     # self.conn_ltk = 'F643BB7D84C1BD6255D485FB8DAAE51A'.decode('hex')
            #     return True

            # if SM_Random in self.pkt:
            # 	print(hexlify(BLESMPServer.get_ltk()))

            # if SM_Pairing_Response in self.pkt:

            # if SM_Pairing_Response in self.pkt:  # PSoC 6 crash
            #     pkt = BTLE('7083329ae015110006008d2a1085d12b5f0dab481c430e6f329bc5c31ee4'.decode('hex'))
            #     self.send(pkt)
            #     return False

            # if SM_Random in self.pkt:  # Telink final crash step
            #     self.conn_ltk = '\x00' * 16
            #     # self.send(BTLE('7083329a0215110006000700000000000000000000000000000000e94bf0'.decode('hex')))
            #     return True

            try:
                smp_answer = BLESMPServer.send_hci(raw(HCI_Hdr() / HCI_ACL_Hdr() / L2CAP_Hdr() / self.pkt[SM_Hdr]))
            except:
                return False
            if smp_answer is not None and isinstance(smp_answer, list):
                for res in smp_answer:
                    print("value of res:")
                    res = HCI_Hdr(res)  # type: HCI_Hdr
                    res.show()
                    if SM_Hdr in res:
                        print("SM_Hdr")
                        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / res[SM_Hdr]
                        pkt.show()
                        self.pairing_starting = True

                        # pkt = BTLE(
                        #     '7083329a0245410006000cd14b70d78dbf394c6b964a089d0656fa8a6eabc4cabadcbfc4c88e67d30ab2356d4ea71fe1899f4c4a74b864e7378b148efb5f121c177f2c8e356772f53629c0a03f55'.decode(
                        #         'hex'))
                        # self.send(pkt)
                        # pkt = BTLE('7083329a021511000600820330c727319c85926c23dc8285f7e4103117db'.decode('hex'))
                        # self.send(pkt)
                        # pkt = BTLE(
                        #     '7083329af145410006004ad14b70d78dbf394c6b964a089d0656fa8a6eabc4cabadcbfc4c88e67d30ab2356d4ea71fe1899f4c4a74b864e7378b148efb5f121c177f2c8e356772f53629c00e4c15'.decode(
                        #         'hex'))
                        # pkt = BTLE(
                        #     '7083329a0245410006000c54c5bb2ff050ee07ec4057d0df637d03895eea28be175615923ff0d1d915e33022e4c03b3497a9b8bdd2e87034f08f147d713a4000771169ebf2efeb38995f5d43f732'.decode(
                        #         'hex'))  # Public key for crashing texas instruments
                        #
                        # pkt = BTLE(
                        #     access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / \
                        #       SM_Public_Key()  # Public key for crashing texas instruments
                        #
                        #     self.send(pkt)

                        # if SM_Confirm in self.pkt:
                        #     # self.send(pkt)
                        #     # pkt = BTLE('7083329a031703000000000000000000009024de9e5d22f2b3ec44db32b3427a'.decode('hex'))
                        #     # self.send(pkt)
                        #     self.conn_ltk = '\x00' * 16
                        #     return True

                        # if SM_Random in self.pkt:  # Brutal attack against texas instruments
                        #     self.conn_ltk = BLESMPServer.get_ltk()
                        #     # self.conn_ltk = 'DB98EC7E029B088CC2339ED185380D90'.decode('hex')
                        #     # self.conn_ltk = '\x00' * 16
                        #     print hexlify(self.conn_ltk)
                        #     return True
                        # if SM_Failed in pkt:
                        #     print(hexlify(BLESMPServer.get_ltk()))
                        #     self.conn_ltk = '\x00' * 16
                        #     # self.conn_ltk = '2DBEED6EA163CD3A597DD3896A5C610B'.decode('hex')
                        #     return True

                        #self.send(pkt)

                        # sleep(0.9)
                        # if SM_Public_Key in pkt:
                        #     self.send_encryption_request()

                    elif HCI_Cmd_LE_Start_Encryption_Request in res:
                        self.conn_ltk = res.ltk
                        self.conn_ediv = res.ediv
                        print(Fore.GREEN + "[!] STK/LTK received from SMP server: " + hexlify(res.ltk).upper())
                        return True

        return False
    
    
    
    def finish_keys(self):

        # if SM_Public_Key in self.pkt:
        #     pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / SM_Confirm()
        #     self.send(pkt)
        #     pass
        print("In finish_pair_response")
        
        # handling error in ble_central
        if self.pkt is None:
            return

        if SM_Hdr in self.pkt:
            self.pkt.show()
            #
            # if SM_Pairing_Response in self.pkt:  # Telink final crash step
            # self.send_encryption_request()
            # self.conn_ltk = '\xFF' * 16
            # self.conn_ltk = '35A54250A0FC76CDC2893054B4096009'.decode('hex')
            # return True

            # if SM_Confirm in self.pkt:
            #     # pkt = BTLE('7083329a0215110006000700000400000000000000000000000000e94bf0'.decode('hex'))
            #     # self.send(pkt)
            #     self.conn_ltk = '\x00' * 16
            #     # self.conn_ltk = 'F643BB7D84C1BD6255D485FB8DAAE51A'.decode('hex')
            #     return True

            # if SM_Random in self.pkt:
            # 	print(hexlify(BLESMPServer.get_ltk()))

            # if SM_Pairing_Response in self.pkt:

            # if SM_Pairing_Response in self.pkt:  # PSoC 6 crash
            #     pkt = BTLE('7083329ae015110006008d2a1085d12b5f0dab481c430e6f329bc5c31ee4'.decode('hex'))
            #     self.send(pkt)
            #     return False

            # if SM_Random in self.pkt:  # Telink final crash step
            #     self.conn_ltk = '\x00' * 16
            #     # self.send(BTLE('7083329a0215110006000700000000000000000000000000000000e94bf0'.decode('hex')))
            #     return True

            try:
                smp_answer = BLESMPServer.send_hci(raw(HCI_Hdr() / HCI_ACL_Hdr() / L2CAP_Hdr() / self.pkt[SM_Hdr]))
            except:
                return False
            if smp_answer is not None and isinstance(smp_answer, list):
                for res in smp_answer:
                    print("value of res:")
                    res = HCI_Hdr(res)  # type: HCI_Hdr
                    res.show()
                    if SM_Hdr in res:
                        print("SM_Hdr")
                        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / res[SM_Hdr]
                        pkt.show()
                        self.pairing_starting = True

                        # pkt = BTLE(
                        #     '7083329a0245410006000cd14b70d78dbf394c6b964a089d0656fa8a6eabc4cabadcbfc4c88e67d30ab2356d4ea71fe1899f4c4a74b864e7378b148efb5f121c177f2c8e356772f53629c0a03f55'.decode(
                        #         'hex'))
                        # self.send(pkt)
                        # pkt = BTLE('7083329a021511000600820330c727319c85926c23dc8285f7e4103117db'.decode('hex'))
                        # self.send(pkt)
                        # pkt = BTLE(
                        #     '7083329af145410006004ad14b70d78dbf394c6b964a089d0656fa8a6eabc4cabadcbfc4c88e67d30ab2356d4ea71fe1899f4c4a74b864e7378b148efb5f121c177f2c8e356772f53629c00e4c15'.decode(
                        #         'hex'))
                        # pkt = BTLE(
                        #     '7083329a0245410006000c54c5bb2ff050ee07ec4057d0df637d03895eea28be175615923ff0d1d915e33022e4c03b3497a9b8bdd2e87034f08f147d713a4000771169ebf2efeb38995f5d43f732'.decode(
                        #         'hex'))  # Public key for crashing texas instruments
                        #
                        # pkt = BTLE(
                        #     access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / SM_Hdr() / \
                        #       SM_Public_Key()  # Public key for crashing texas instruments
                        #
                        #     self.send(pkt)

                        # if SM_Confirm in self.pkt:
                        #     # self.send(pkt)
                        #     # pkt = BTLE('7083329a031703000000000000000000009024de9e5d22f2b3ec44db32b3427a'.decode('hex'))
                        #     # self.send(pkt)
                        #     self.conn_ltk = '\x00' * 16
                        #     return True

                        # if SM_Random in self.pkt:  # Brutal attack against texas instruments
                        #     self.conn_ltk = BLESMPServer.get_ltk()
                        #     # self.conn_ltk = 'DB98EC7E029B088CC2339ED185380D90'.decode('hex')
                        #     # self.conn_ltk = '\x00' * 16
                        #     print hexlify(self.conn_ltk)
                        #     return True
                        # if SM_Failed in pkt:
                        #     print(hexlify(BLESMPServer.get_ltk()))
                        #     self.conn_ltk = '\x00' * 16
                        #     # self.conn_ltk = '2DBEED6EA163CD3A597DD3896A5C610B'.decode('hex')
                        #     return True

                        self.send(pkt)

                        # sleep(0.9)
                        # if SM_Public_Key in pkt:
                        #     self.send_encryption_request()

                    elif HCI_Cmd_LE_Start_Encryption_Request in res:
                        self.conn_ltk = res.ltk
                        self.conn_ediv = res.ediv
                        print(Fore.GREEN + "[!] STK/LTK received from SMP server: " + hexlify(res.ltk).upper())
                        return True

        return False

    def send_encryption_request(self):
        print("in send_encryption_request")
        # if self.conn_encryted is False:
        self.conn_ediv = '\x00'  # this is 0 on first time pairing
        self.conn_rand = '\x00'  # this is 0 on first time pairing
        self.conn_iv = '\x00' * 4  # set IVm (IV of master)
        self.conn_skd = '\x00' * 8
        # self.conn_iv = os.urandom(4)  # set IVm (IV of master)
        # self.conn_skd = os.urandom(8)
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_ENC_REQ(ediv=self.conn_ediv,
                                                                                                rand=self.conn_rand,
                                                                                                skdm=self.conn_skd,
                                                                                                ivm=self.conn_iv)
        # pkt[BTLE_DATA].LLID = 0
        pkt.show()
        # pkt = BTLE('7083329a0817032300000000000000000001e23444f17c9f6bb128c485c3ba21'.decode('hex')) # llid=0
        # pkt = BTLE('7083329a1717030000000000000000000096d20461af85f4ae6f09bcc0c2c239'.decode('hex'))  # md=1
        # pkt[BTLE_DATA].MD = 1
        self.send(pkt)

    def send_start_encryption_response(self):
        global scan_response_received
        print("value of scan_response_received: "+str(scan_response_received))
        self.conn_encryted = True  # Enable encryption for tx/rx
        if scan_response_received:
            pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_START_ENC_RSP()
            pkt.show()
            # pkt = BTLE('7083329a170105d85a9e'.decode('hex'))
            self.send(pkt)
        else:
            self.conn_encryted = False


    def send_start_encryption_response_plain(self):
        saved = self.conn_encryted
        self.conn_encryted = False  # Enable encryption for tx/rx
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_START_ENC_RSP()
        pkt.show()
        # pkt = BTLE('7083329a170105d85a9e'.decode('hex'))
        self.send(pkt)
        self.conn_encryted = saved

    def send_encryption_pause_request(self):
        global scan_response_received
        print("value of scan_response_received: "+str(scan_response_received))
        self.conn_encryted = True  # Enable encryption for tx/rx
        if scan_response_received:
            pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_PAUSE_ENC_REQ()
            pkt.show()
            # pkt = BTLE('7083329a170105d85a9e'.decode('hex'))
            self.send(pkt)
        else:
            self.conn_encryted = False

    def send_encryption_pause_request_plain(self):
        saved = self.conn_encryted
        self.conn_encryted = False
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_PAUSE_ENC_REQ()
        pkt.show()
        # pkt = BTLE('7083329a170105d85a9e'.decode('hex'))
        self.send(pkt)
        self.conn_encryted = saved

    def send_encryption_pause_response(self):
        global scan_response_received
        print("value of scan_response_received: "+str(scan_response_received))
        self.conn_encryted = True  # Enable encryption for tx/rx
        if scan_response_received:
            pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_PAUSE_ENC_RSP()
            pkt.show()
            # pkt = BTLE('7083329a170105d85a9e'.decode('hex'))
            self.send(pkt)
        else:
            self.conn_encryted = False


    def send_encryption_pause_response_plain(self):
        saved = self.conn_encryted
        self.conn_encryted = False  # Enable encryption for tx/rx
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_PAUSE_ENC_RSP()
        pkt.show()
        # pkt = BTLE('7083329a170105d85a9e'.decode('hex'))
        self.send(pkt)
        self.conn_encryted = saved

    def receive_encryption_response(self):

        # if LL_ENC_RSP in self.pkt:  # Telink final crash step
        #     self.send_version_indication()
        #     return True
        self.pkt.show()
        if LL_ENC_RSP in self.pkt:
            #if self.conn_skd or self.conn_iv is None:
                #return
            
            # e(key, plain text) - most significant octet first
            try:
                self.conn_skd += self.pkt.skds  # SKD = SKDm || SKDs
                self.conn_iv += self.pkt.ivs  # IV = IVm || IVs
                #self.conn_ltk = '\x00' * 16
                #self.conn_ltk = '\x00' * 16
                #self.conn_session_key = self.bt_crypto_e(self.conn_ltk[::-1], self.conn_skd[::-1])
                #print (type(self.conn_session_key))
                #print(hexlify(self.conn_session_key).upper())
                #print(self.conn_session_key)
                #saved = self.conn_ltk
                #self.conn_ltk = "89636BFD51934823830967B66AFDB7CC".decode("hex")
                #self.conn_ltk =  "00000000000000000000000000000000".decode("hex")
                self.conn_session_key = self.bt_crypto_e(self.conn_ltk[::-1], self.conn_skd[::-1])
                #self.conn_session_key = self.bt_crypto_e('\x00' * 16, self.conn_skd[::-1])
                #print(hexlify(self.conn_ltk).upper())
                #self.conn_session_key = "47E1451AC021F30F8B4B0D5BCED8D080".decode("hex")
                print(hexlify(self.conn_ltk).upper())
                print(hexlify(self.conn_skd).upper())
                print(hexlify(self.conn_session_key).upper())
                #if(saved == self.conn_session_key):
                    #print("same")
                #else:
                    #print("not same")

            except:
                print('error and generating static key of all 00')
                print(traceback.format_exc())
                self.pkt.show()
                self.conn_ltk = "00000000000000000000000000000000".decode("hex")
                try:
                    self.conn_session_key = self.bt_crypto_e(self.conn_ltk[::-1], self.conn_skd[::-1])
                    print(hexlify(self.conn_ltk).upper())
                    print(hexlify(self.conn_skd).upper())
                    print(hexlify(self.conn_session_key).upper())
                except:
                    self.conn_skd = "00000000000000000000000000000000".decode("hex")
                    self.conn_session_key = self.bt_crypto_e(self.conn_ltk[::-1], self.conn_skd[::-1])
                    print(hexlify(self.conn_ltk).upper())
                    print(hexlify(self.conn_skd).upper())
                    print(hexlify(self.conn_session_key).upper())


            self.conn_master_packet_counter = 0


        # elif LL_START_ENC_REQ in self.pkt:
        # self.conn_encryted = True  # Enable encryption for tx/rx
        # pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_START_ENC_RSP()
        # pkt = BTLE('7083329a170105d85a9e'.decode('hex'))
        # self.send(pkt)
        # self.send(BTLE('d6be898e030c81d7f059970016554312cfa4199308'.decode('hex')))
        # self.send_encryption_request()
        # self.send(BTLE('7083329a86cf063288db'.decode('hex')))
        # self.send_encryption_request()
        # pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_ENC_REQ(ediv=self.conn_ediv,
        #                                                                                         rand=self.conn_rand,
        #                                                                                         skdm=self.conn_skd,
        #                                                                                         ivm=os.urandom(4))
        # self.send(pkt)

        elif LL_START_ENC_RSP in self.pkt:
            print(Fore.GREEN + "[!] !!! Link Encrypted direct in host !!!")
            # self.send_feature_response()
            return True

        # if Raw in self.pkt:
        #     print('oi')
        #     self.v += 1
        #     if self.v == 2:
        #         self.send_version_indication()
        #         self.send_encryption_request()

        # if LL_REJECT_IND in self.pkt:
        #     self.send_encryption_request()

        return False

    def finish_key_exchange(self):
        if SM_Hdr in self.pkt:
            self.machine.reset_state_timeout()
            try:
                smp_answer = BLESMPServer.send_hci(raw(HCI_Hdr() / HCI_ACL_Hdr() / L2CAP_Hdr() / self.pkt[SM_Hdr]))
                if smp_answer is not None and isinstance(smp_answer, list):
                    for res in smp_answer:
                        res = HCI_Hdr(res)  # type: HCI_Hdr
                        if SM_Hdr in res:
                            pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / res[SM_Hdr]
                            self.sent_packet = pkt
                            # if SM_Identity_Address_Information in pkt:
                            #     pkt = BTLE('7083329a4315110006000a0000000000000000000000000000000080ce78'.decode('hex'))
                            #     self.send(pkt)
                            #     return False
                            self.send(pkt)
            except:
                pass

        return False

    # # non-fragmentation code 
    def send_public_key_invalid(self):
         if SM_Hdr is None or self.pkt is None:
             return
         if SM_Hdr in self.pkt:
             try:
                 hci_res = BLESMPServer.send_public_key()
                 print("hci_res modified")
                 #print(hci_res)
                 if hci_res:
                     print("IK in: ")
                     pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[
                         SM_Hdr]
                     pkt.show()
                     pkt[SM_Public_Key].key_x = b'\xff' * 32
                     pkt[SM_Public_Key].key_y = b'\xff' * 32
                     print("after modification IK: ")
                     pkt.show()
                     self.send(pkt)
             except:
                 pass

    def send_public_key(self):
         if SM_Hdr is None or self.pkt is None:
             return
         if SM_Hdr in self.pkt:
             try:
                 hci_res = BLESMPServer.send_public_key()
                 print("hci_res modified")
                 #print(hci_res)
                 if hci_res:
                     print("IK in: ")
                     pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[
                         SM_Hdr]
                     pkt.show()
                     self.send(pkt)
             except:
                 pass


    # fragmentation code 
    def send_public_key_invalid_frag(self):
        if SM_Hdr is None or self.pkt is None:
            return
        if SM_Hdr in self.pkt:                  
            try:
                hci_res = BLESMPServer.send_public_key()
                print("hci_res modified invalid") 
                print("HEX:")
                print(binascii.hexlify(hci_res).upper())
                data = HCI_Hdr(hci_res)
                data.show()
                data[SM_Public_Key].key_x = b'\xff' * 32
                data[SM_Public_Key].key_y = b'\xff' * 32
                data.show()
                if hci_res:
                    if HCI_ACL_Hdr in data and len(data.getlayer(HCI_ACL_Hdr)) > 27:
                        l2CapHdr = data.getlayer(L2CAP_Hdr)
                        #l2CapHdr.show()
                        #l2CapHdr[SM_Public_Key].key_x = b'\xff' * 32
                        #l2CapHdr[SM_Public_Key].key_y = b'\xff' * 32
                        l2CapLen = len(l2CapHdr.payload)
                        l2CapHdr.len = l2CapLen
                        print("l2CapLen: " + str(l2CapLen))
                        payloadToSend = raw(l2CapHdr)
                        print("payloadToSend: " + str(len(raw(l2CapHdr))))
                        print("Total Payload: "+ binascii.hexlify(payloadToSend.upper()))
                        first = True
                        first_again = 0
                        while len(payloadToSend) > 0:
                            currPacketLen = 27 if len(payloadToSend) > 27 else len(payloadToSend)
                            packet = HCI_Hdr() / HCI_ACL_Hdr()
                            if first:
                                first = False
                                packet.PB = 0x2
                            else:
                                packet.PB = 0x1
                            packet.add_payload(payloadToSend[:currPacketLen])
                            print("Total Payload: "+ binascii.hexlify(payloadToSend.upper()))
                            print("Current Payload: "+ binascii.hexlify(payloadToSend[:currPacketLen].upper()))
                            print("IK in payload creations iterations: "+ str(first_again))
                            packet.show()
                            if first_again == 2:
                                pkt3 = BTLE(access_addr=self.conn_access_address) / BTLE_DATA(LLID = 1) / payloadToSend[:currPacketLen]
                                print("HEX: "+binascii.hexlify(raw(pkt3)).upper())
                                self.send(pkt3)
                                first_again = first_again + 1
                                #sleep(0.2)
                            if first_again == 1:
                                pkt2 = BTLE(access_addr=self.conn_access_address) / BTLE_DATA(LLID = 1) / payloadToSend[:currPacketLen]
                                first_again = first_again + 1
                                print("HEX: "+binascii.hexlify(raw(pkt2)).upper())
                                self.send(pkt2)
                                #sleep(0.2)
                            if first_again == 0:
                                #sleep(0.2)
                                pkt1 = BTLE(access_addr=self.conn_access_address) / BTLE_DATA(LLID = 2) / payloadToSend[:currPacketLen]
                                first_again = first_again + 1
                                print("HEX: "+ binascii.hexlify(raw(pkt1)).upper())
                                raw_pk1 = raw(pkt1)
                                self.send(pkt1)
                                #sleep(0.2)
                            #pkt.show()
                            #self.send(packet)
                            payloadToSend = payloadToSend[currPacketLen:]
                    else:
                        print("IK out: ")
                        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]
                        pkt.show()
                        self.send(pkt)   
            except:
                pass


    def send_public_key_frag(self):
        if SM_Hdr is None or self.pkt is None:
            return
        if SM_Hdr in self.pkt:
            try:
                hci_res = BLESMPServer.send_public_key()
                print("hci_res modified") 
                print("HEX:")
                print(binascii.hexlify(hci_res).upper())
                data = HCI_Hdr(hci_res)
                data.show()
                if hci_res:
                    if HCI_ACL_Hdr in data and len(data.getlayer(HCI_ACL_Hdr)) > 27:
                        l2CapHdr = data.getlayer(L2CAP_Hdr)
                        l2CapLen = len(l2CapHdr.payload)
                        l2CapHdr.len = l2CapLen
                        print("l2CapLen: " + str(l2CapLen))
                        payloadToSend = raw(l2CapHdr)
                        print("payloadToSend: " + str(len(raw(l2CapHdr))))
                        print("Total Payload: "+ binascii.hexlify(payloadToSend.upper()))
                        first = True
                        first_again = 0
                        while len(payloadToSend) > 0:
                            currPacketLen = 27 if len(payloadToSend) > 27 else len(payloadToSend)
                            packet = HCI_Hdr() / HCI_ACL_Hdr()
                            if first:
                                first = False
                                packet.PB = 0x2
                            else:
                                packet.PB = 0x1
                            packet.add_payload(payloadToSend[:currPacketLen])
                            print("Total Payload: "+ binascii.hexlify(payloadToSend.upper()))
                            print("Current Payload: "+ binascii.hexlify(payloadToSend[:currPacketLen].upper()))
                            print("IK in payload creations iterations: "+ str(first_again))
                            packet.show()
                            if first_again == 2:
                                pkt3 = BTLE(access_addr=self.conn_access_address) / BTLE_DATA(LLID = 1) / payloadToSend[:currPacketLen]
                                print("HEX: "+binascii.hexlify(raw(pkt3)).upper())
                                self.send(pkt3)
                                first_again = first_again + 1
                                #sleep(0.2)
                            if first_again == 1:
                                pkt2 = BTLE(access_addr=self.conn_access_address) / BTLE_DATA(LLID = 1) / payloadToSend[:currPacketLen]
                                first_again = first_again + 1
                                print("HEX: "+binascii.hexlify(raw(pkt2)).upper())
                                self.send(pkt2)
                                #sleep(0.2)
                            if first_again == 0:
                                #sleep(0.2)
                                pkt1 = BTLE(access_addr=self.conn_access_address) / BTLE_DATA(LLID = 2) / payloadToSend[:currPacketLen]
                                first_again = first_again + 1
                                print("HEX: "+ binascii.hexlify(raw(pkt1)).upper())
                                raw_pk1 = raw(pkt1)
                                self.send(pkt1)
                                #sleep(0.2)
                            #pkt.show()
                            #self.send(packet)
                            payloadToSend = payloadToSend[currPacketLen:]
                    else:
                        print("IK out: ")
                        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[SM_Hdr]
                        pkt.show()
                        self.send(pkt)   
            except:
                pass
        


    def send_dh_check(self):
        if SM_Hdr is None or self.pkt is None:
            return
        if SM_Hdr in self.pkt:
            try:
                hci_res = BLESMPServer.send_dh_check()
                print("dh_check")
                print(hci_res)
                if hci_res:
                    pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[
                        SM_Hdr]
                    pkt.show()
                    self.send(pkt)
            except:
                pass

    def send_dh_check_invalid(self):
        if SM_Hdr is None or self.pkt is None:
            return
        if SM_Hdr in self.pkt:
            try:
                hci_res = BLESMPServer.send_dh_check()
                print("dh_check invalid")
                print(hci_res)
                if hci_res:
                    pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[
                        SM_Hdr]
                    pkt.show()
                    pkt[SM_DHKey_Check].dhkey_check = ""
                    self.send(pkt)
            except:
                pass
    def send_sign_info(self):
        if SM_Hdr is None or self.pkt is None:
            return
        if SM_Hdr in self.pkt:
            try:
                hci_res = BLESMPServer.send_sign_info()
                print("hci_res")
                print(hci_res)
                hci_res.show()
                if hci_res:
                    pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[
                        SM_Hdr]
                    pkt.show()
                    self.send(pkt)
            except:
                pass

    def send_sm_random(self):
        # print("Reached send_sm_random()")
        # print("SM_Hdr: ", SM_Hdr)
        # print("self.pkt: ", self.pkt)
        if SM_Hdr is None or self.pkt is None:
            return
        if SM_Hdr in self.pkt or True:          # forcefully making it true
            try:
                hci_res = BLESMPServer.send_sm_random()
                # print("Completed : BLESMPServer.send_sm_random()")
                print("hci_res")
                print(hci_res)
                if hci_res:
                    pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[
                        SM_Hdr]
                    pkt.show()
                    self.send(pkt)
            except:
                pass
        # else:
        #     print("SM_Hdr NOT in self.pkt")


    def send_pair_confirm(self):
        if SM_Hdr is None or self.pkt is None:
            return
        if SM_Hdr in self.pkt:
            try:
                hci_res = BLESMPServer.send_pair_confirm()
                print("hci_res")
                print(hci_res)
                if hci_res:
                    pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[
                        SM_Hdr]
                    pkt.show()
                    self.send(pkt)
            except:
                pass

    def send_pair_confirm_wrong_value(self):
        if SM_Hdr is None or self.pkt is None:
            return
        if SM_Hdr in self.pkt:
            try:
                hci_res = BLESMPServer.send_pair_confirm()
                print("hci_res")
                print(hci_res)
                if hci_res:
                    pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / L2CAP_Hdr() / HCI_Hdr(hci_res)[
                        SM_Hdr]
                    pkt.show()
                    print("after!!\n\n\n\n\n\n\n\n")
                    saved = pkt[SM_Confirm].confirm
                    pkt[SM_Confirm].confirm = saved[3:16]
                    pkt.show()
                    self.send(pkt)
            except:
                pass

    def send_pri_services_request(self):
        self.slave_next_start_handle = None
        if self.slave_next_start_handle is None:
            self.att.read_by_group_type(0x0001, 0xffff, 0x2800, None)
        else:
            self.att.read_by_group_type(self.slave_next_start_handle, 0xffff, 0x2800, None)

    v = 0

    def receive_pri_services(self):
        # if LL_LENGTH_REQ in self.pkt:
        #     self.send_length_response()
        print("receive_pri_services")
        # self.pkt.show()
        if ATT_Read_By_Group_Type_Response in self.pkt:
            pkt = self.pkt[ATT_Read_By_Group_Type_Response]
            # if self.v >= 3:
            #     pkt = BTLE('7083329a020b070006000103d73710048c07709c'.decode('hex'))
            #     self.send(pkt)
            #     return False
            # self.v += 1

            if self.discover_gatt_services(pkt, 0x2800):
                self.slave_next_start_handle = None
                print(Fore.GREEN + "[!] End of primary service discovery")
                return True
        elif ATT_Error_Response in self.pkt:
            self.slave_next_start_handle = None
            print(Fore.GREEN + "[!] Primary service discovered")
            return True

    d = 0

    def send_sec_services_request(self):
        self.slave_next_start_handle = None
        # pkt = BTLE('7083329a020804000400121100000d5b3a'.decode('hex'))  # Crash STM WB55
        # self.send(pkt)  # Crash STM WB55
        # self.att.read_by_group_type(0x0001, 0xffff, 0x2801, None)  # required

        # self.att.read_by_group_type(0x0001, 0xffff, 0x2801, None)
        # self.att.read_by_group_type(0x0001, 0xffff, 0x2801, None)

        if self.slave_next_start_handle is None:
            print("Main case: slave is none\n")
            self.att.read_by_group_type(0x0001, 0xffff, 0x2801, None)
        else:
            print("Else case: slave is not none\n")
            # self.att.read_by_group_type(0x0001, 0xffff, 0x2801, None)
            self.att.read_by_group_type(self.slave_next_start_handle, 0xffff, 0x2801, None)
        # if self.d == 0:
        #     pkt = BTLE('7083329a020b07000400100100c45201281bb789'.decode('hex'))
        #     self.send(pkt)
        #     self.d = 1

    def receive_sec_services(self):
        if ATT_Read_By_Group_Type_Response in self.pkt:
            pkt = self.pkt[ATT_Read_By_Group_Type_Response]
            if self.discover_gatt_services(pkt, 0x2801):
                self.slave_next_start_handle = None
                print(Fore.GREEN + "[!] End of secondary service discovery")
                return True
        elif ATT_Error_Response in self.pkt:
            self.slave_next_start_handle = None
            print(Fore.GREEN + "[!] Secondary service discovered")
            return True

    def discover_gatt_services(self, pkt, request_uuid):

        length = pkt.length
        service_data = pkt.data
        bluetooth_base_addr = "00000000-0000-1000-8000-00805F9B34FB".replace('-', '')
        try:
            if length == 6:  # 4 byte uuid, 2 2-byte handles
                print(Fore.RED + "[IK] Length 6" + "service data " + str(len(service_data)))
                # print("We've got services with 16-bit UUIDs!")
                services = []
                i = 0
                end_loop = False
                while i < len(service_data):
                    services.append(service_data[i:i + 6])
                    i += 6
                # print "Services:", services
                for service in services:
                    try:
                        start = struct.unpack("<h", service[:2])[0]
                        end = struct.unpack("<h", service[2:4])[0]
                        uuid_16 = struct.unpack("<h", service[4:])[0]
                        conversion = (uuid_16 * (2 ** 96)) + int(bluetooth_base_addr, 16)
                        uuid_128 = struct.pack(">QQ", (conversion >> 64) & 0xFFFFFFFFFFFFFFFF,
                                               conversion & 0xFFFFFFFFFFFFFFFF).encode('hex')
                        uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))
                        if end == -1:
                            end = 0xffff
                        if start == -1:
                            start = 0xffff
                        self.slave_device.add_service(start, end, uuid_128)
                        if end >= 0xFFFF or end < 0:
                            end_loop = True
                        if self.slave_next_start_handle is None or end >= self.slave_next_start_handle:
                            self.slave_next_start_handle = end + 1
                    except:
                        continue
                if end_loop:
                    return True
            elif length == 20:  # 16 byte uuid, 2 2-byte handles
                # print("We've got services with 128-bit UUIDs!")
                start = struct.unpack("<h", service_data[:2])[0]
                end = struct.unpack("<h", service_data[2:4])[0]
                uuid_128 = struct.unpack("<QQ", service_data[4:])
                uuid_128 = "%016x%016x" % (uuid_128[1], uuid_128[0])
                # print "UUID128:", uuid_128
                uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))
                if end == -1:
                    end = 0xffff
                if start == -1:
                    start = 0xffff
                self.slave_device.add_service(start, end, uuid_128)
                if end >= 0xFFFF or end < 0:
                    return True
                self.slave_next_start_handle = end + 1
            else:
                print(Fore.RED + "[!] UNEXPECTED PRIMARY SERVICE DISCOVERY RESPONSE. BAILING")
        except:
            pass
            # Send next group type request (next services to discover)
        self.att.read_by_group_type(self.slave_next_start_handle, 0xffff, request_uuid, None)
        return False

    def send_characteristics_request(self):
        self.slave_next_start_handle = None
        if self.slave_next_start_handle is None:
            self.att.read_by_type(0x0001, 0xffff, 0x2803, None)
        else:
            self.att.read_by_type(self.slave_next_start_handle, 0xffff, 0x2803, None)

    def receive_characteristics(self):
        # Note: This is not exactly the procedure described in the spec (BLUETOOTH SPECIFICATION Version 5.0 |
        # Vol 3, Part G page 2253-4), but it's independent of a service scan.

        if ATT_Error_Response in self.pkt:
            print(Fore.GREEN + "[!] Characteristics discoved")
            self.slave_next_start_handle = None
            return True

        if ATT_Read_By_Type_Response not in self.pkt:
            return False

        characteristic_data = raw(self.pkt[ATT_Read_By_Type_Response])
        bluetooth_base_addr = "00000000-0000-1000-8000-00805F9B34FB".replace('-', '')

        length = int(characteristic_data[0].encode('hex'), 16)
        characteristic_data = characteristic_data[1:]

        if length == 7:  # 4byte uuid, 2 2-byte handles, 1 byte permission
            # print("We've got services with 16-bit UUIDs!")
            characteristics = []
            i = 0
            end_loop = False
            while i < len(characteristic_data):
                characteristics.append(characteristic_data[i:i + 7])
                i += 7
            # print "Services:", services
            for characteristic in characteristics:
                handle = struct.unpack("<h", characteristic[:2])[0]
                perm = struct.unpack("<B", characteristic[2:3])[0]
                value_handle = struct.unpack("<h", characteristic[3:5])[0]
                print ("handle: " + hex(handle))
                print ("perm: " + hex(perm))
                # print "UUID_16:", characteristic[5:].encode('hex')
                uuid_16 = struct.unpack("<h", characteristic[5:])[0]
                conversion = (uuid_16 * (2 ** 96)) + int(bluetooth_base_addr, 16)
                uuid_128 = struct.pack(">QQ", (conversion >> 64) & 0xFFFFFFFFFFFFFFFF,
                                       conversion & 0xFFFFFFFFFFFFFFFF).encode('hex')
                uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))
                if handle == -1:
                    handle = 0xffff
                if value_handle == -1:
                    value_handle = 0xffff
                self.slave_device.add_characteristic(value_handle, handle, uuid_128, perm)
                if handle >= 0xFFFF or handle < 0:
                    end_loop = True
                if self.slave_next_start_handle is None or handle > self.slave_next_start_handle:
                    self.slave_next_start_handle = handle + 1
            if end_loop:
                print(Fore.GREEN + "[!] End of characteristic discovery!")
                self.slave_next_start_handle = None
                return True
        elif length == 21:  # 16 byte uuid, 2 2-byte handles, 1 byte permission
            # print("We've got services with 128-bit UUIDs!")
            handle = struct.unpack("<h", characteristic_data[:2])[0]
            perm = struct.unpack("<B", characteristic_data[2:3])[0]
            value_handle = struct.unpack("<h", characteristic_data[3:5])[0]
            #print(Fore.GREEN + "[X] Characteristics skiped")
            #return True
            print ("handle 21 length: " + hex(handle))
            print ("perm 21 length: " + hex(perm))
            uuid_128 = struct.unpack("<QQ", characteristic_data[5:])
            uuid_128 = "%016x%016x" % (uuid_128[1], uuid_128[0])
            # print "UUID128:", uuid_128
            uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))
            if handle == -1:
                handle = 0xffff
            if value_handle == -1:
                value_handle = 0xffff
            self.slave_device.add_characteristic(value_handle, handle, uuid_128, perm)
            if handle >= 0xFFFF or handle < 0:
                print(Fore.GREEN + "[!] End of characteristic discovery!")
                self.slave_next_start_handle = None
                return True
            self.slave_next_start_handle = handle + 1
        else:
            print("[!] UNEXPECTED INCLUDE DISCOVERY RESPONSE. BAILING. Length: " + str(length))

        self.att.read_by_type(self.slave_next_start_handle, 0xffff, 0x2803, None)
        return False

    def send_includes_request(self):
        self.slave_next_start_handle = None
        if self.slave_next_start_handle is None:
            self.att.read_by_type(0x0001, 0xffff, 0x2802, None)
        else:
            self.att.read_by_type(self.slave_next_start_handle, 0xffff, 0x2802, None)

    def receive_includes(self):

        if ATT_Error_Response in self.pkt:
            print(Fore.GREEN + "[!] Includes discoved")
            self.slave_next_start_handle = None
            return True

        if ATT_Read_By_Type_Response not in self.pkt:
            return False


        include_data = raw(self.pkt[ATT_Read_By_Type_Response])
        length = int(include_data[0].encode('hex'), 16)
        include_data = include_data[1:]

        if length == 8:  # 2 byte handle of this attribute, 2 byte uuid, 2 end group handle, 2 byte handle of included service declaration
            # logger.debug("We've got includes with 16-bit UUIDs!")
            includes = []
            i = 0
            end_loop = False
            while i < len(include_data):
                includes.append(include_data[i:i + 7])
                i += 7
            # print "Services:", services
            for incl in includes:
                handle = struct.unpack("<H", incl[:2])[0]
                included_att_handle = struct.unpack("<H", incl[2:4])[0]
                end_group_handle = struct.unpack("<H", incl[4:6])[0]
                # print "UUID_16:", characteristic[5:].encode('hex')
                try:
                    included_service_uuid_16 = struct.unpack("<H", incl[6:])[0]
                except:
                    return True
                if handle == -1:
                    handle = 0xffff
                self.slave_device.add_include(handle, included_att_handle, end_group_handle, included_service_uuid_16)
                if handle >= 0xFFFF or handle < 0:
                    end_loop = True
                if self.slave_next_start_handle is None or handle > self.slave_next_start_handle:
                    self.slave_next_start_handle = handle + 1
            if end_loop:
                print(Fore.GREEN + "[!] End of include discovery!")
                self.slave_next_start_handle = None
                return True
        elif length == 6:  # 2 byte handle of this attribute, 2 end group handle, 2 byte handle of included service declaration
            # logger.debug("[!] We've got services with 128-bit UUIDs!")
            handle = struct.unpack("<H", include_data[:2])[0]
            included_att_handle = struct.unpack("<H", include_data[2:4])[0]
            end_group_handle = struct.unpack("<H", include_data[4:6])[0]
            if handle == -1:
                handle = 0xffff
            self.slave_device.add_include(handle, included_att_handle, end_group_handle, None)
            if handle >= 0xFFFF or handle < 0:
                print(Fore.GREEN + "[!] End of include discovery!")
                self.slave_next_start_handle = None
                return True
            self.slave_next_start_handle = handle + 1
        else:
            print("[!] UNEXPECTED INCLUDE DISCOVERY RESPONSE. BAILING. Length: " + str(length))

        self.att.read_by_type(self.slave_next_start_handle, 0xffff, 0x2802, None)
        return False

    def send_descriptors_request(self):
        self.slave_next_start_handle = None
        if self.slave_next_start_handle is None:
            self.slave_service_idx = None
            self.slave_characteristic_idx = None
            service = None
            characteristic = None
            i = 0
            j = 0

            if self.slave_device is None:
                return

            # Get the index of the first service and characteristic available
            for _i, _service in enumerate(self.slave_device.services):
                found = False
                for _j, _characteristic in enumerate(_service.characteristics):
                    service = self.slave_device.services[_i]
                    characteristic = _service.characteristics[_j]
                    i = _i
                    j = _j
                    found = True
                    break
                if found is True:
                    break

            if characteristic is None:
                self.att.find_information(None, 0x0001, 0xFFFF)
                return

            start = characteristic.handle + 1
            if (len(service.characteristics) - 1) is 0:
                if (len(self.slave_device.services) - 1) is 0:
                    end = service.end
                else:
                    end = self.slave_device.services[i + 1].start - 1
            else:
                end = service.characteristics[j + 1].handle - 1

            if end == -1 or end > 0xffff:
                end = 0xffff
            if start == -1:
                start = 0xffff

            self.slave_service_idx = i
            self.slave_characteristic_idx = j + 1
            self.slave_characteristic = characteristic
        else:
            start = self.slave_next_start_handle
            end = self.slave_next_end_handle
        self.att.find_information(None, start, end)

    cq = 0

    def receive_descriptors(self):

        # if ATT_Exchange_MTU_Response in self.pkt:
        #     self.send_encryption_request()
        # Compute information response and add to slave_device object
        if ATT_Find_Information_Response in self.pkt:
            # self.send_encryption_request()
            # if self.cq == 0:
            #     self.send_mtu_length_request()
            #     self.cq = 1

            bluetooth_base_addr = "00000000-0000-1000-8000-00805F9B34FB".replace('-', '')
            data = raw(self.pkt[ATT_Find_Information_Response])[1:]
            uuid_format = self.pkt[ATT_Find_Information_Response].format
            if uuid_format == 1:  # 16 bit uuid
                mark = 0
                descriptors = []
                while mark < len(data):
                    descriptors.append(data[mark:mark + 4])  # 2 byte handle, 2 byte uuid
                    mark += 4
                for desc in descriptors:
                    try:
                        handle = struct.unpack("<h", desc[:2])[0]
                        uuid_16 = struct.unpack("<h", desc[2:])[0]
                        conversion = (uuid_16 * (2 ** 96)) + int(bluetooth_base_addr, 16)
                        uuid_128 = struct.pack(">QQ", (conversion >> 64) & 0xFFFFFFFFFFFFFFFF,
                                               conversion & 0xFFFFFFFFFFFFFFFF).encode('hex')
                        uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16],
                                             uuid_128[16:20], uuid_128[20:]))
                        if self.slave_characteristic is not None:
                            self.slave_characteristic.add_descriptor_with_data(handle, uuid_128, None)
                    except:
                        return False

            elif uuid_format == 2:  # 128-bit uuid
                handle = struct.unpack("<h", data[:2])[0]
                uuid_128 = struct.unpack("<QQ", data[2:])
                uuid_128 = "%016x%016x" % (uuid_128[1], uuid_128[0])
                uuid_128 = '-'.join((uuid_128[:8], uuid_128[8:12], uuid_128[12:16], uuid_128[16:20], uuid_128[20:]))

                self.slave_characteristic.add_descriptor_with_data(handle, uuid_128, None)
        #print("\n\n\nReached line 2711 in Desc\n\n\n")
        #self.pkt.show()
        # Iterate over the characteristics of the slave_device and send accordingly
        if ATT_Find_Information_Response in self.pkt or ATT_Error_Response in self.pkt:

            i = self.slave_service_idx
            j = self.slave_characteristic_idx

            if i is None or j is None:
                return False

            if self.slave_device.services is None or len(self.slave_device.services) is 0:
                print(Fore.YELLOW + '[!] No descriptors listed')
                self.update_slave_handles()
                self.slave_next_start_handle = None
                self.slave_next_end_handle = None
                return True

            if self.slave_device.services[i].characteristics is not None and j >= len(
                    self.slave_device.services[i].characteristics):
                print('recebido 2')
                i += 1
                j = 0

                if i >= len(self.slave_device.services):
                    print(Fore.GREEN + '[!] Descriptors discovered')
                    # Proceed
                    self.update_slave_handles()
                    self.slave_next_start_handle = None
                    self.slave_next_end_handle = None

                    # pkt = BTLE('7083329a020703000400642d1451bf17'.decode('hex'))
                    # self.send(pkt)
                    return True

                elif self.slave_device.services[i].characteristics is None or len(
                        self.slave_device.services[i].characteristics) is 0:
                    self.slave_service_idx += 1
                    print(Fore.RED + '[!] WRONG 2766')
                    return False
            elif self.slave_device.services[i].characteristics is None:
                self.slave_service_idx += 1
                return False

            service = self.slave_device.services[i]
            characteristic = service.characteristics[j]

            start = characteristic.handle + 1
            if j >= len(service.characteristics) - 1:
                if i >= len(self.slave_device.services) - 1:
                    end = service.end
                else:
                    end = self.slave_device.services[i + 1].start - 1
            else:
                end = service.characteristics[j + 1].handle - 1

            self.slave_service_idx = i
            self.slave_characteristic_idx = j + 1
            self.slave_characteristic = characteristic
            self.slave_next_start_handle = start
            self.slave_next_end_handle = end
            self.att.find_information(None, start, end)
            return False

        return False

    def send_read_request(self):
        if self.slave_handles is None:
            print("slave_handles is None!!")
            return
        if len(self.slave_handles) > 0:
            try:
                self.att.read(self.slave_handles[self.slave_handles_idx], None)
            except:
                pass
        self.slave_handles_idx += 1


    def finish_readings(self):

        if ATT_Read_Response in self.pkt:
            pkt = self.pkt[ATT_Read_Response]
            try:
                self.slave_handles_values.update({self.slave_handles[self.slave_handles_idx - 1]: pkt.value})
            except:
                pass

        if (ATT_Hdr in self.pkt and self.pkt[ATT_Hdr].opcode is 0x0B) or ATT_Error_Response in self.pkt:
            self.v += 1
            if ATT_Error_Response in self.pkt:
                e = self.pkt[ATT_Error_Response].ecode
                if e in _att_error_codes:
                    print("Error code: " + _att_error_codes[e])
                else:
                    print(Fore.RED + "Error code: " + str(e))

            if self.slave_handles_idx < len(self.slave_handles):
                self.send_read_request()

                # if self.v == 3:
                #     pkt = BTLE('7083329a0207030004000aee7baf87d9'.decode('hex'))
                #     self.send(pkt)
                # if self.v == 8:
                #     pkt = BTLE('7083329a02070300040016258f549e09'.decode('hex'))
                #     self.send(pkt)
            else:
                print(Fore.GREEN + '[!] Readings finished')
                self.slave_handles_idx = 0
                return True
        if self.slave_handles_idx > len(self.slave_handles):
            self.slave_handles_idx = 0
            print(Fore.GREEN + '[!] Readings finished')
            return True
        return False

    def send_write_request(self):

        try:
            if self.slave_handles[self.slave_handles_idx] in self.slave_handles_values:
                value = self.slave_handles_values[self.slave_handles[self.slave_handles_idx]]
            else:
                value = '\x00'
            self.att.write_req(self.slave_handles[self.slave_handles_idx], value, None)
        except:
            print("caught exception in send_write_request")
            pass
        if self.slave_handles_idx is None:
            return
        self.slave_handles_idx += 1

    def finish_writing(self):

        if (ATT_Write_Response in self.pkt) or ATT_Error_Response in self.pkt:

            if ATT_Error_Response in self.pkt:
                e = self.pkt[ATT_Error_Response].ecode
                if e in _att_error_codes:
                    print("Error code: " + _att_error_codes[e])
                else:
                    print(Fore.RED + "Error code: " + str(e))

            if self.slave_handles_idx < len(self.slave_handles):
                # pkt = BTLE('7083329a0208040004003e0700003a7135'.decode('hex'))
                # self.send(pkt)
                self.send_write_request()
            else:
                print(Fore.GREEN + '[!] Writting finished')
                self.slave_handles_idx = 0
                return True
        if self.slave_handles_idx > len(self.slave_handles):
            self.slave_handles_idx = 0
            print(Fore.GREEN + '[!] Writting finished')
            return True

    def send_disconn_request(self):
        pkt = BTLE(access_addr=self.conn_access_address) / BTLE_DATA() / CtrlPDU() / LL_TERMINATE_IND(code=0x13)
        self.send(pkt)


def client_handler(client_socket):
    # reboot_env(device,environment)
    global command
    global acl_frag_flag
    model = BLECentralMethods(None, None,
                              master_mtu = 247,  # 23 default, 247 max (mtu must be 4 less than max length)
                            #   master_address='a4:c1:38:d8:ad:a9', # will take these inputs from from socket
                            #   slave_address='1c:1b:b5:1e:52:5c',   # will take these inputs from a git ignored config file
                              dongle_serial_port='/dev/ttyACM0',
                              baudrate=115200,
                              monitor_magic_string='ESP-IDF v4.1', enable_fuzzing=False,
                              enable_duplication=False, client_socket=client_socket)
    while True:
        # data received from client
        data = client_socket.recv(1024)

        if not data:
            print('Bye')
            # lock released on exit
            print_lock.release()
            break

        command = data.lower()

        print("* COMMAND RECEIVED  :", command, "*")
        command = command.strip().split()[-1]
        print("* CHANGED COMMAND:", command, "*")

        if "reset" in command:
            #model.master_address = str(RandMAC()).upper()
            print("Received reset command!")
            model.reset_vars()
            model.send_disconn_request()
            # model.reset_dongle_connection()
            #model.sniff()
            model.disable_timeout('conn_supervision_timer')
            model.disable_timeout('conn_general_timer')
            model.conn_ediv = '\x00'  # this is 0 on first time pairing
            model.conn_rand = '\x00'  # this is 0 on first time pairing
            #model.conn_ediv = '\x00'  # this is 0 on first time pairing
            #model.conn_rand = '\x00'  # this is 0 on first time pairing
            #model.conn_iv = '\x00' * 4  # set IVm (IV of master)
            #model.conn_skd = '\x00' * 8
            client_socket.send('DONE\n')
        
        if "probe_enc_status" in command:
            print("Received probe_enc_status command!")
            client_socket.send(str(model.conn_encryted)+"\n")

        if "discon_req" in command:
            print("Received discon_req command!")
            model.conn_encryted = False
            model.conn_slave_packet_counter = 0
            model.send_disconn_request()
            client_socket.send('DONE\n')

        elif "scan_req" in command:
            model.send_scan_request()
            model.sniff()

        elif "enc_req" in command:
            print("received enc_req from learner")
            model.send_encryption_request()
            model.sniff()


        elif "start_enc_resp_plain" in command:
            print("received start_enc_resp_plain from learner")
            model.send_start_encryption_response_plain()
            model.sniff()


        elif "enc_pause_resp_plain" in command:
            print("received enc_pause_resp_plain from learner")
            model.send_encryption_pause_response_plain()
            model.sniff()


        elif "enc_pause_req_plain" in command:
            print("received enc_pause_req_plain from learner")
            model.send_encryption_pause_request_plain()
            model.sniff()

        elif "enc_pause_resp" in command:
            print("received enc_pause_resp from learner")
            model.send_encryption_pause_response()
            model.sniff()
            
        elif "enc_pause_req" in command:
            print("received enc_pause_req from learner")
            model.send_encryption_pause_request()
            model.sniff()        

        elif "start_enc_resp" in command:
            print("received start_enc_resp from learner")
            model.send_start_encryption_response()
            model.sniff()


        elif "sec_service_req" in command:
            print("received sec_service_req from learner")
            model.send_sec_services_request()
            model.sniff()



        elif "feature_resp_none" in command:
            print("received feature response none")
            model.send_feature_response_feature_set_zero()
            model.sniff()

        elif "feature_resp" in command:
            print("received feature response")
            model.send_feature_response()
            #sleep(0.5)
            #model.send_feature_response()
            # sleep(1)
            # model.send_feature_response()
            model.sniff()
        
        elif "mtu_resp_llid_zero" in command:
            print("received mtu_req_llid_zero from learner")
            model.send_mtu_length_response_llid_zero()
            model.sniff()

        elif "mtu_resp_mtu_zero" in command:
            print("received mtu_req_mtu_zero from learner")
            model.send_mtu_length_response_mtu_zero()
            model.sniff()

        elif "mtu_resp" in command:
            print("received mtu response from learner")
            model.send_mtu_length_response()
            model.sniff()


        elif "mtu_req_llid_zero" in command:
            print("received mtu_req_llid_zero from learner")
            model.send_mtu_length_request_llid_zero()
            model.sniff()

        elif "mtu_req_mtu_zero" in command:
            print("received mtu_req_mtu_zero from learner")
            model.send_mtu_length_request_mtu_zero()
            model.sniff()

        elif "mtu_req" in command:
            print("received mtu_req from learner")
            model.send_mtu_length_request()
            model.sniff()

        elif "con_req_length_zero" in command:
            print("received con_req_length_zero from learner")
            timeout = 5
            model.send_connection_request_length_zero()
            model.sniff()

        elif "con_req_channel_map_zero" in command:
            print("received con_req_channel_map_zero from learner")
            timeout = 5
            model.send_connection_request_channel_map_zero()
            model.sniff()

        elif "con_req_hop_zero" in command:
            print("received con_req_hop_zero from learner")
            timeout = 5
            model.send_connection_request_hop_zero()
            model.sniff()


        elif "con_req_timeout_zero" in command:
            print("received con_req_timeout_zero from learner")
            timeout = 5
            model.send_connection_request_timeout_zero()
            model.sniff()

        elif "con_req_crc_zero" in command:
            print("received con_req_crc_zero from learner")
            timeout = 5
            model.send_connection_request_crc_zero()
            model.sniff()

        elif "con_req_interval_zero" in command:
            print("received con_req_interval_zero from learner")
            timeout = 5
            model.send_connection_request_interval_zero()
            model.sniff()


        elif "con_req" in command:
            timeout = 5
            model.send_connection_request()
            if "steval" in device:
                model.sniff(5)
            else:
                model.sniff()


        elif "key_exchange_invalid" in command:
            print("received key_exchange_invalid from learner")
            if acl_frag_flag:
                model.send_public_key_invalid_frag()
            else:
                model.send_public_key_invalid()
            model.sniff()

        elif "key_exchange" in command:
            print("received key_exchange from learner")
            if acl_frag_flag:
                model.send_public_key_frag()
            else:
                model.send_public_key()
            model.sniff()

        elif "dh_check_invalid" in command:
            print("received dh_check_invalid from learner")
            model.send_dh_check_invalid()
            model.sniff()



        elif "dh_check" in command:
            print("received dh_check from learner")
            model.send_dh_check()
            model.sniff()



        elif "pri_req" in command:
            print("received pri_req from learner")
            model.send_pri_services_request()
            model.sniff()



        elif "pair_req_no_sc_bonding" in command:
            print("received pair_req_no_sc_bonding from learner")
            model.send_pair_request_no_sc_bonding()
            model.sniff(5)


        elif "pair_req_no_sc_keyboard_display" in command:
            print("received pair_req_no_sc_keyboard_display from learner")
            model.send_pair_request_no_sc_keyboard_display()
            model.sniff(5)

        elif "pair_req_no_sc_display_yes_no" in command:
            print("received pair_req_no_sc_display_yes_no from learner")
            model.send_pair_request_no_sc_display_yes_no()
            model.sniff(5)

        elif "pair_req_no_sc" in command:
            print("received pair_req_no_sc from learner")
            model.send_pair_request_no_sc()
            model.sniff(5)



        elif "char_req" in command:
            print("received char_req from learner")
            model.send_characteristics_request()
            model.sniff()

        elif "pair_req_key_zero" in command:
            print("received pair_req_key_zero from learner")
            model.send_pair_request_key_zero()
            model.sniff(5)

        elif "pair_req_oob" in command:
            print("received pair_req_oob from learner")
            model.send_pair_request_oob()
            model.sniff(5)

        elif "pair_req_keyboard_display" in command:
            print("received pair_req_keyboard_display from learner")
            model.send_pair_request_keyboard_display()
            model.sniff(5)


        elif "pair_req_display_yes_no" in command:
            print("received pair_req_display_yes_no from learner")
            model.send_pair_request_display_yes_no()
            model.sniff(5)

        elif "pair_req" in command:
            print("received pair_req from learner")
            model.send_pair_request()
            model.sniff(5)

        elif "sign_info" in command:
            print("received sign_info from learner")
            model.send_sign_info()
            model.sniff()



        elif "version_req_llid_zero" in command:
            print("received version_req_llid_zero from learner")
            model.send_version_indication_llid_zero()
            model.sniff()

        elif "version_req_max_len" in command:
            print("received version_req_max_len from learner")
            model.send_version_indication_max_len()
            model.sniff()

        elif "version_req" in command:
            print("received version_req from learner")
            model.send_version_indication()
            model.sniff()
            
        elif "pair_confirm_wrong_value" in command:
            print("received pair_confirm_wrong_value from learner")
            model.send_pair_confirm_wrong_value()
            model.sniff()

        elif "pair_confirm" in command:
            print("received pair_confirm from learner")
            model.send_pair_confirm()
            model.sniff(5)



        elif "sm_random_send" in command:
            print("received sm_random_send from learner")
            model.send_sm_random()
            model.sniff()

        elif "desc_req" in command:
            print("received desc_req from learner")
            model.send_descriptors_request()
            model.sniff()


        elif "includes_req" in command:
            print("received includes_req from learner")
            model.send_includes_request()
            model.sniff()



        elif "read" in command:
            print("received read from learner")
            model.send_read_request()
            model.sniff()

        elif "write" in command:
            print("received write from learner")
            model.send_write_request()
            model.sniff()



        elif "length_req_rx_tx_zero" in command:
            print("!!received length_req_rx_tx_zero!!")
            model.send_length_request_zero_rx_tx()
            model.sniff(4)

        elif "length_req_time_zero" in command:
            print("!!received length_req_time_zero!!")
            model.send_length_request_zero_time()
            model.sniff(4)

        elif "length_req" in command:
            print("!!received length request!!")
            model.send_length_request()
            model.sniff(4)

        elif "length_resp_rx_tx_zero" in command:
            print("!!received length response!!")
            model.send_length_response_zero_rx_tx()
            #sleep(1)
            #model.send_mtu_length_response()
            model.sniff()
        
        elif "length_resp_time_zero" in command:
            print("!!received length response!!")
            model.send_length_response_zero_time()
            #sleep(1)
            #model.send_mtu_length_response()
            model.sniff()

        elif "length_resp" in command:
            print("!!received length response!!")
            model.send_length_response()
            #sleep(1)
            #model.send_mtu_length_response()
            model.sniff()


        elif "feature_req_none" in command:
            print ("received feature_req_none")
            model.send_feature_request_feature_set_zero()
            model.sniff(4)

        elif "feature_req" in command:
            print ("received feature request")
            model.send_feature_request()
            model.sniff(2)

        elif "pri_resp" in command:
            model.send_pri_services_response()
            model.sniff()

        #elif "ue_reboot" in command:
        #    handle_ue_reboot(client_socket)

        #elif "adb_server_restart" in command:
        #    handle_adb_server_restart(client_socket)


        elif "update_slave_address" in command:
            print("received update_slave_address from learner:")
            new_slave_address = command.split("-")[1].strip()
            print("received new_slave_address:", new_slave_address)
            model.adjust_slave_addr(new_slave_address)
            print("updated slave address with :", new_slave_address)
            model.client_socket.send("DONE\n")

    client_socket.close()


# model.get_graph().draw('bluetooth/ble_central.png', prog='dot')

def Main():
    global device
    global acl_frag_flag
    host = ""
    port = 60000
    if (len(sys.argv)<2):
        print 'Usage: ble_central.py <device name> bluez, nexus6...'
        exit()
    device = sys.argv[1]
    print("Device: "+device )
    if "huaweiy5" in device or "htcdesire10" in device or "cy63" in device:
        acl_frag_flag = True
    else:
        acl_frag_flag = False
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    print("socket binded to post", port)
    s.listen(5)
    print("socket is listening")

    while True:
        # establish connection with client
        client_socket, addr = s.accept()

        # lock acquired by client
        print_lock.acquire()
        print('Connected to :', addr[0], ':', addr[1])

        # Start a new thread and return its identifier
        start_new_thread(client_handler, (client_socket,))
    s.close()


if __name__ == '__main__':
    Main()
