from twisted.internet.protocol import Factory
from tcp.server.protocol import ServerProtocol


class ServerFactory(Factory):

    def __init__(self, client_endpoint, tcp_host, crypto, replay, frida_script, arguments):
        self.client_endpoint = client_endpoint
        self.tcp_host = tcp_host
        self.crypto = crypto
        self.replay = replay
        self.frida_script = frida_script
        self.args = arguments

    def buildProtocol(self, _):
        return ServerProtocol(self)
