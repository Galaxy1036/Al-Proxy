from colorama import Fore, Style
from twisted.internet.protocol import Protocol

from utils import hexdump
from tcp.proxy import setup_proxy
from tcp.packetReceiver import packetReceiver
from tcp.packet.packetEnum import packet_enum


class ClientProtocol(packetReceiver, Protocol):

    def __init__(self, factory):
        self.factory = factory
        self.factory.server.client = self
        self.server = self.factory.server

    def connectionMade(self):
        self.peer = self.transport.getPeer()
        print('{}[*] Connected to {}:{}'.format(Style.RESET_ALL, self.peer.host, self.peer.port))

    def connectionLost(self, reason):
        print('{}[*] Server closed the connection !'.format(Style.RESET_ALL))
        self.server.transport.loseConnection()

    def processPacket(self, packet_id, packet_data):
        if packet_id in packet_enum:
            packet_name = packet_enum[packet_id]

        else:
            packet_name = packet_id

            if self.server.factory.args.frida:
                self.server.factory.frida_script.post({
                    'type': 'packetName',
                    'packetId': packet_id
                })

        print('{}[*] {} received from server, length: {}'.format(Fore.MAGENTA, packet_name, len(packet_data)))

        if self.server.factory.args.verbose:
            print(hexdump(packet_data))

        if self.server.factory.args.replay:
            self.server.factory.replay.save_packet('{}-Server'.format(packet_name), packet_data)

        if packet_name in ('PatchServerAddressResponse', 'ConnectToZoneService_0001'):
            if packet_name == 'PatchServerAddressResponse':
                print('{}[*] Client asked for the patch server adress, redirecting to a new proxy'.format(Fore.YELLOW))

            else:
                print('{}[*] Client asked for a zone server adress, redirecting a new proxy'.format(Fore.YELLOW))

            servers_count = int.from_bytes(packet_data[0:2], 'little')

            if servers_count:
                server_ip_parts = [int.from_bytes(packet_data[i + 2:i + 3], 'little') for i in range(4)]
                server_ip_parts.reverse()

                server_ip = '.'.join(map(str, server_ip_parts))
                server_port = int.from_bytes(packet_data[6:8], 'little')

                proxy_port = setup_proxy(
                    server_ip, server_port,
                    self.server.factory.tcp_host,
                    self.server.factory.crypto,
                    self.server.factory.replay,
                    self.server.factory.frida_script,
                    self.server.factory.args
                )

                tcp_host_parts = list(map(int, self.server.factory.tcp_host.split('.')))
                tcp_host_parts.reverse()

                modified_packet_data = (1).to_bytes(2, 'little') + bytes(tcp_host_parts) + proxy_port.to_bytes(2, 'little')

                if packet_name == 'ConnectToZoneService_0001':
                    modified_packet_data += packet_data[2 + servers_count * 6:]  # IMPORTANT VALUE, used to allow connection

                packet_data = modified_packet_data

            else:
                print('{}[x] Couldn\'t find server adress, aborting...'.format(Fore.RED))

        data = len(packet_data).to_bytes(4, 'little') + packet_id.to_bytes(4, 'little') + packet_data
        self.server.transport.write(data)
