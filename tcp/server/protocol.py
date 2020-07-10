from colorama import Fore, Style
from twisted.internet import reactor
from twisted.internet.protocol import Protocol

from utils import hexdump
from tcp.client.factory import ClientFactory
from tcp.packetReceiver import packetReceiver
from tcp.packet.packetEnum import encrypted_packets, packet_enum


class ServerProtocol(packetReceiver, Protocol):

    def __init__(self, factory):
        self.factory = factory
        self.factory.server = self
        self.client = None

    def connectionMade(self):
        self.peer = self.transport.getPeer()
        print('{}[*] New connection from {}'.format(Style.RESET_ALL, self.peer.host))
        self.factory.client_endpoint.connect(ClientFactory(self))

    def connectionLost(self, reason):
        print('{}[*] Client disconnected !'.format(Style.RESET_ALL))

        if self.client:
            self.client.transport.loseConnection()

    def processPacket(self, packet_id, packet_data):
        if not self.client:
            reactor.callLater(0.25, self.processPacket, packet_id, packet_data)
            return

        if packet_id in packet_enum:
            packet_name = packet_enum[packet_id]

        else:
            packet_name = packet_id

            if self.factory.args.frida:
                self.factory.frida_script.post({
                    'type': 'packetName',
                    'packetId': packet_id
                })

        is_encrypted = packet_name in encrypted_packets

        if is_encrypted:
            try:
                packet_data = self.factory.crypto.decrypt_client_packet(packet_data)

            except ValueError:
                print('{}[x] Failed to decrypt packet {}, aborting ...'.format(Fore.RED, packet_name))
                reactor.stop()
                return

        print('{}[*] {} received from client, length: {}'.format(Fore.BLUE, packet_name, len(packet_data)))

        if self.factory.args.verbose:
            print(hexdump(packet_data))

        if self.factory.args.replay:
            self.factory.replay.save_packet('{}-Client'.format(packet_name), packet_data)

        if is_encrypted:
            packet_data = self.factory.crypto.encrypt_client_packet(packet_data)

        data = len(packet_data).to_bytes(4, 'little') + packet_id.to_bytes(4, 'little') + packet_data

        self.client.transport.write(data)
