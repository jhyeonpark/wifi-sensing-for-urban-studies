# Importing packages
import os, time
from multiprocessing import Pool
# Importing packages
import signal, requests, csv
import sys
import hashlib
import os
import logging
import traceback
import random
import time
import multiprocessing
import threading
import Queue
import sqlite3
import pcapy
import dpkt
import socket
import struct
import datetime as dt
from multiprocessing import Process
import os, time
import dropbox
from dropbox.exceptions import ApiError, AuthError
from requests.exceptions import ConnectionError
import picamera, threading
import sys, os
import socket
import schedule
import requests, subprocess
import os, time, schedule
from multiprocessing import Process
from subprocess import Popen, PIPE
import subprocess
import time, schedule, socket, sqlite3, os
import binascii

channel_wlan1 = '1'  # 2.4GHz only
interface_wlan1 = 'wlan1mon'
monitor_enable_wlan1 = 'ifconfig wlan1 down; iw dev wlan1 interface add wlan1mon type monitor; ifconfig wlan1mon down; iw dev wlan1mon set type monitor; ifconfig wlan1mon up'
monitor_disable_wlan1 = 'iw dev wlan1mon del; ifconfig wlan1 up'
change_channel_wlan1 = 'iw dev wlan1mon set channel %s'

queue = multiprocessing.Queue()

subtypes_management = {
    0: 'association-request',
    1: 'association-response',
    2: 'reassociation-request',
    3: 'reassociation-response',
    4: 'probe-request',
    5: 'probe-response',
    8: 'beacon',
    9: 'announcement-traffic-indication-message',
    10: 'disassociation',
    11: 'authentication',
    12: 'deauthentication',
    13: 'action'
}

subtypes_control = {
    8: 'block-acknowledgement-request',
    9: 'block-acknowledgement',
    10: 'power-save-poll',
    11: 'request-to-send',
    12: 'clear-to-send',
    13: 'acknowledgement',
    14: 'contention-free-end',
    15: 'contention-free-end-plus-acknowledgement'
}

subtypes_data = {
    0: 'data',
    1: 'data-and-contention-free-acknowledgement',
    2: 'data-and-contention-free-poll',
    3: 'data-and-contention-free-acknowledgement-plus-poll',
    4: 'null',
    5: 'contention-free-acknowledgement',
    6: 'contention-free-poll',
    7: 'contention-free-acknowledgement-plus-poll',
    8: 'qos-data',
    9: 'qos-data-plus-contention-free-acknowledgement',
    10: 'qos-data-plus-contention-free-poll',
    11: 'qos-data-plus-contention-free-acknowledgement-plus-poll',
    12: 'qos-null',
    14: 'qos-contention-free-poll-empty'
}


# filename = 'raw_wifi_' + device_name + '.sqlite3'
def writer():
    date_string = time.strftime("%Y-%m-%d") + "HMS" + time.strftime("%H_%M_%S")
    filename = 'wifi_' + date_string + '.sqlite3'
    db = sqlite3.connect('/home/pi/' + filename)
    db.text_factory = str

    def write(stop):
        while not stop.is_set():
            try:
                logging.info('Writing...')
                cursor = db.cursor()
                for _ in range(0, queue.qsize()):
                    item = queue.get_nowait()
                    insert = (
                        "insert into packets values"
                        "("
                        ":timestamp,"
                        ":type,"
                        ":subtype,"
                        ":strength,"
                        ":source_address,"
                        ":destination_address,"
                        ":access_point_name,"
                        ":access_point_address,"
                        ":sequence_number,"
                        ":channel"
                        ")"
                    )
                    cursor.execute(insert.decode('utf-8'), item)
                db.commit()
                cursor.close()
                time.sleep(1)  # seconds
            except Queue.Empty:
                pass
            except KeyboardInterrupt:
                pass

    cursor = db.cursor()
    create = (
        "create table if not exists packets"
        "("
        "timestamp,"
        "type,"
        "subtype,"
        "strength,"
        "source_address,"
        "destination_address,"
        "access_point_name,"
        "access_point_address,"
        "sequence_number,"
        "channel"
        ")"
    )
    cursor.execute(create.decode('utf-8'))
    db.commit()
    cursor.close()
    stop = multiprocessing.Event()
    multiprocessing.Process(target=write, args=[stop]).start()
    return stop


def to_address(address):  # decode a MAC or BSSID address
    return ':'.join('%02x' % ord(b) for b in address)


# Sniffing with the interface wlan and channel
def sniff(interface, channel):
    max_packet_size = -1  # bytes
    promiscuous = 1  # boolean masquerading as an int
    timeout = 1  # milliseconds
    packets = pcapy.open_live(interface, max_packet_size, promiscuous, timeout)
    packets.setfilter('')  # bpf syntax (empty string = everything)

    def loops(header, data):
        try:
            timestamp = dt.datetime.now().isoformat()
            packet = dpkt.radiotap.Radiotap(data)
            packet_signal = -(256 - packet.ant_sig.db)  # dBm
            frame = packet.data
            packet_len = socket.ntohs(packet.length)
            index = packet_len + 22

            try:
                i, = struct.unpack("<H", data[index:index + 2])
                seq = i >> 4
            except struct.error:
                seq = 'NULL'
                frag = 'NULL'


            if frame.type == dpkt.ieee80211.MGMT_TYPE and subtypes_management[frame.subtype] != 'beacon':
                record = {
                    'timestamp': timestamp,
                    'type': 'management',
                    'subtype': subtypes_management[frame.subtype],
                    'strength': packet_signal,
                    'source_address': to_address(frame.mgmt.src),
                    'destination_address': to_address(frame.mgmt.dst),
                    'access_point_name': frame.ssid.data if hasattr(frame, 'ssid') else '(n/a)',
                    'access_point_address': to_address(frame.mgmt.bssid),
                    'sequence_number': seq,
                    'channel': channel
                }
                queue.put(record)
            elif frame.type == dpkt.ieee80211.DATA_TYPE:
                record = {
                    'timestamp': timestamp,
                    'type': 'data',
                    'subtype': subtypes_data[frame.subtype],
                    'strength': packet_signal,
                    'source_address': to_address(frame.data_frame.src),
                    'destination_address': to_address(frame.data_frame.dst),
                    'access_point_name': '(n/a)',  # not available in data packets
                    'access_point_address': to_address(frame.data_frame.bssid) if hasattr(frame.data_frame,
                                                                                          'bssid') else '(n/a)',
                    'sequence_number': seq,
                    'channel': channel
                }
                queue.put(record)
        except Exception as e:
            logging.error(traceback.format_exc())

    packets.loop(-1, loops)


def bluetooth_sniff():
    # Bluetooth sniffing
    print('Sniffing Bluetooth')
    os.system('Bluelog/bluelog -n -t -f -a 5 -d')
    time.sleep(1)


def upload():
    date_string = time.strftime("%Y-%m-%d") + "HMS" + time.strftime("%H_%M_%S")
    filename_storage = 'storage_' + date_string + '.txt'
    os.system('df -h' + ' > ' + filename_storage)

    filename_list = 'list_' + date_string + '.txt'
    os.system('ls -alh' + ' > ' + filename_list)

    
    ## Loading
    upsentence = '/home/pi/Dropbox-Uploader/dropbox_uploader.sh upload' + ' ' + '/home/pi/' + filename_storage + ' ' + '/'
    os.system(upsentence)
    time.sleep(1)

    upsentence1 = '/home/pi/Dropbox-Uploader/dropbox_uploader.sh upload' + ' ' + '/home/pi/' + filename_list + ' ' + '/'
    os.system(upsentence1)

    ## Waiting the uploading


def start():
    ## Synchronize the time
    os.system('sudo apt-get install ntpdate')  # Install network server
    time.sleep(1)
    os.system('sudo ntpdate -u 3.kr.pool.ntp.org')  # Download network server clock
    time.sleep(1)
    os.system('sudo timedatectl set-timezone Asia/Seoul')  # time-set for Asia/Seoul
    time.sleep(1)

    ## Upload battery status and list of the pi to dropbox
    upload()
    time.sleep(5)

    ## Monitor mode setting
    os.system(monitor_enable_wlan1)
      os.system('sudo ifconfig wlan0 down')
    time.sleep(1)

    ## Change the channel to 1, 6, and 11
    os.system(change_channel_wlan1 % channel_wlan1)
    ## Bluetooth off
    os.system('sudo systemctl disable bluetooth.service')
    ## Turn off the HDMI for saving battery
    os.system('sudo /opt/vc/bin/tvservice -o')

    time.sleep(1)

    stop_writing = writer()
    try:
        print('start wlan1')
        w1 = Process(target=sniff, args=(interface_wlan1, channel_wlan1))

        w1.start()
  
        w1.join()

    except KeyboardInterrupt:
        sys.exit()

    finally:
        stop_writing.set()
        os.system(monitor_disable_wlan1)
      
start()
