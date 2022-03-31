## Import packages
import os, time
from multiprocessing import Pool
import sys, signal, requests, csv, hashlib, binascii, subprocess, logging, traceback, random
import time, multiprocessing, threading, Queue, sqlite3, pcapy, dpkt, socket, struct, 
import datetime as dt
from multiprocessing import Process
import dropboxm, picamera, schedule
from dropbox.exceptions import ApiError, AuthError
from requests.exceptions import ConnectionError

## Set channels to be monitored
channel_wlan1 = '6'  # 1 of 2.4GHz
interface_wlan1 = 'wlan1mon'
monitor_enable_wlan1 = 'ifconfig wlan1 down; iw dev wlan1 interface add wlan1mon type monitor; ifconfig wlan1mon down; iw dev wlan1mon set type monitor; ifconfig wlan1mon up'
monitor_disable_wlan1 = 'iw dev wlan1mon del; ifconfig wlan1 up'
change_channel_wlan1 = 'iw dev wlan1mon set channel %s'

## Set device name
device_name = 'WiFi_sensor_1'

queue = multiprocessing.Queue()

## Set WiFi frame
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

## Set writer
def writer():
    date_string = time.strftime("%Y-%m-%d_%H")
    filename = 'raw_wifi_' + date_string + '_' + device_name + '.sqlite3' # Filename setting using written date and device_name 
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
                        ":hashed_source_address,"
                        ":destination_address,"
                        ":hashed_dest_address,"
                        ":access_point_name,"
                        ":access_point_address,"
                        ":device_name,"
                        ":sequence_number,"
                        ":channel,"
                        ":info"
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
        "hashed_source_address,"
        "destination_address,"
        "hashed_dest_address,"
        "access_point_name,"
        "access_point_address,"
        "device_name,"
        "sequence_number,"
        "channel,"
        "info"
        ")"
    )
    cursor.execute(create.decode('utf-8'))
    db.commit()
    cursor.close()
    stop = multiprocessing.Event()
    multiprocessing.Process(target=write, args=[stop]).start()
    return stop


## Accessing MAC addresses as alphabet and number
def to_address(address):  # decode a MAC or BSSID address
    return ':'.join('%02x' % ord(b) for b in address)

## Sniffing with the interface wlan and channel
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
            infor = binascii.hexlify(data).decode()
            try:
                i, = struct.unpack("<H", data[index:index + 2])
                seq = i >> 4
            except struct.error:
                seq = 'NULL'
                frag = 'NULL'

            # Hashing MAC addresses for privacy issues
            try:
                hashed_source_address = hashlib.sha256(to_address(frame.mgmt.src).encode('utf-8')).hexdigest()[:12]
                hashed_dest_address = hashlib.sha256(to_address(frame.mgmt.dst).encode('utf-8')).hexdigest()[:12]
            except AttributeError:
                hashed_source_address = 'NULL'
                hashed_dest_address = 'NULL'
            
            if frame.type == dpkt.ieee80211.MGMT_TYPE and subtypes_management[frame.subtype] != 'beacon':
                record = {
                    'timestamp': timestamp,
                    'type': 'management',
                    'subtype': subtypes_management[frame.subtype],
                    'strength': packet_signal,
                    'source_address': to_address(frame.mgmt.src),
                    'hashed_source_address': hashed_source_address,
                    'destination_address': to_address(frame.mgmt.dst),
                    'hashed_dest_address': hashed_dest_address,
                    'access_point_name': frame.ssid.data if hasattr(frame, 'ssid') else '(n/a)',
                    'access_point_address': to_address(frame.mgmt.bssid),
                    'device_name': device_name,
                    'sequence_number': seq,
                    'channel': channel,
                    'info': infor
                }
                queue.put(record)

            elif frame.type == dpkt.ieee80211.DATA_TYPE:
                record = {
                    'timestamp': timestamp,
                    'type': 'data',
                    'subtype': subtypes_data[frame.subtype],
                    'strength': packet_signal,
                    'source_address': to_address(frame.data_frame.src),
                    'hashed_source_address': hashed_source_address,
                    'destination_address': to_address(frame.data_frame.dst),
                    'hashed_dest_address': hashed_dest_address,
                    'access_point_name': '(n/a)',  # not available in data packets
                    'access_point_address': to_address(frame.data_frame.bssid) if hasattr(frame.data_frame,
                                                                                          'bssid') else '(n/a)',
                    'device_name': device_name,
                    'sequence_number': seq,
                    'channel': channel,
                    'info': infor
                }
                queue.put(record)
        except Exception as e:
            logging.error(traceback.format_exc())

    packets.loop(-1, loops)

## Bluetooth setting
def bluetooth_sniff():
    # Bluetooth sniffing
    print('Sniffing Bluetooth')
    os.system('Bluelog/bluelog -n -t -f -a 5 -d')
    time.sleep(1)

## Uploading small data on Dropbox
def upload_turnoff():
    # Making last txt of Wi-Fi results
    date_string = time.strftime("%Y-%m-%d_%H")
    filename = 'raw_wifi_' + date_string + '_' + device_name + '.sqlite3'
    connection = sqlite3.connect('/home/pi/' + filename)
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM packets ORDER BY timestamp DESC LIMIT 10")
    result = cursor.fetchone()
    connection.close()

    list_file = os.listdir('/home/pi')
    list_file = sorted(list_file)
    list_file_str = '\n'.join(list_file)

    with open('/home/pi/' + filename + '_last.txt', "w") as f:
        for i in range(10):
            f.write(str(result))
        f.write(list_file_str)

    time.sleep(5)

    upsentence = "/home/pi/Dropbox-Uploader/dropbox_uploader.sh upload" + " " + '/home/pi/' + filename + '_last.txt' + " " + '/wifi/'
    subprocess.Popen(upsentence, shell=True)
    time.sleep(15)
    os.system('sudo ifconfig wlan0 down')


## Starting sensing
def start():

    bluetooth_sniff() # Bluetooth sniffing
    t = threading.Timer(15, upload_turnoff)
    t.start()

    os.system(monitor_enable_wlan1)

    time.sleep(5)
    os.system(change_channel_wlan1 % channel_wlan1)
    
    print('Writing')
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
