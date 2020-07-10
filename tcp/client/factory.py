from twisted.internet.protocol import ClientFactory as ClientFactoryImpl

from tcp.client.protocol import ClientProtocol


class ClientFactory(ClientFactoryImpl):

    def __init__(self, server):
        self.server = server

    def buildProtocol(self, addr):
        return ClientProtocol(self)
