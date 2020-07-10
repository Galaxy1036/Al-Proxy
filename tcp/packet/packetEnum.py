import os
import sys
import json

from colorama import Fore

from utils import crc32c


if os.path.isfile('tcp/packet/packet_names.json'):
    with open('tcp/packet/packet_names.json') as f:
        packet_names = json.load(f)

else:
    sys.exit('{}[x] Missing packet_names.json, cannot continue'.format(Fore.RED))


encrypted_packets = [
    'UserCredentialsMessage_0004',
    'ZoneServiceLogin'
]


packet_enum = {crc32c(packet_name.encode('utf-8')): packet_name for packet_name in packet_names}
