import os
import sys
import json
import time
import argparse
import frida

from colorama import init, Style
from twisted.web import server
from twisted.internet import reactor

from replay import Replay
from tcp.crypto import RsaCrypto
from tcp.proxy import setup_proxy
from tcp.packet.packetEnum import packet_names
from web.web_server import Webroot


MAX_FRIDA_RETRY = 10


def on_close():
    print('{}[*] Closing proxy !'.format(Style.RESET_ALL))


def on_frida_message(message, _):
    if message['type'] == 'send':
        if message['payload']['type'] == 'packetName':
            packet_names.append(message['payload']['packetName'])

        with open('tcp/packet/packet_names.json', 'w') as f:
            f.write(json.dumps(packet_names))


def start_frida_script():
    try:
        device = frida.get_usb_device()

    except Exception as exception:
        sys.exit('[*] Can\'t connect to your device ({}) !'.format(exception.__class__.__name__))

    print('[*] Successfully connected to frida server !')

    pid = device.spawn(['sts.al'])

    retry_count = 0
    process = None

    while not process:
        try:
            process = device.attach(pid)

        except Exception as exception:
            if retry_count == MAX_FRIDA_RETRY:
                sys.exit('[*] Can\'t attach frida to the game ({}) ! Start the frida server on your device'.format(exception.__class__.__name__))

            retry_count += 1
            time.sleep(0.5)

    print('[*] Frida attached !')

    if os.path.isfile('al_hook.js'):
        script = process.create_script(open('al_hook.js').read())

    else:
        sys.exit('[*] gl_hook.js script is missing, cannot inject the script !')

    script.on('message', on_frida_message)
    script.load()
    device.resume(pid)

    print('[*] Script injected !')

    return script


if __name__ == '__main__':
    init()
    parser = argparse.ArgumentParser(description='Python proxy used to dump & decrypt Arcane Legends packet')
    parser.add_argument('-v', '--verbose', help='print packet hexdump in console', action='store_true')
    parser.add_argument('-r', '--replay', help='save packets in replay folder', action='store_true')
    parser.add_argument('-f', '--frida', help='automatically grab missing packet names using a frida script', action='store_true')

    args = parser.parse_args()

    if os.path.isfile('config.json'):
        config = json.load(open('config.json'))

    else:
        sys.exit('[*] config.json is missing !')

    if args.frida:
        frida_script = start_frida_script()

    else:
        frida_script = None

    site = server.Site(Webroot())
    host_info = reactor.listenTCP(80, site).getHost()

    print("[*] Web Server is listening on {}:{}".format(host_info.host, host_info.port))

    setup_proxy(config['Hostname'], config['Port'], config['TCPHost'], RsaCrypto(), Replay(config['ReplayDirectory']), frida_script, args)

    reactor.addSystemEventTrigger('before', 'shutdown', on_close)
    reactor.run()
