class packetReceiver:

    buffer = b''
    packet = b''

    def dataReceived(self, data):
        self.buffer += data

        while self.buffer:
            if self.packet:
                packet_id = int.from_bytes(self.packet[4:8], 'little')
                packet_length = int.from_bytes(self.packet[0:4], 'little')

                if len(self.buffer) >= packet_length:
                    self.packet += self.buffer[:packet_length]
                    self.processPacket(packet_id, self.packet[8:])
                    self.packet = b''
                    self.buffer = self.buffer[packet_length:]

                else:
                    break

            elif len(self.buffer) >= 8:
                self.packet = self.buffer[:8]

                if len(self.buffer) == 8 and int.from_bytes(self.packet[0:4], 'little') == 0:
                    packet_id = int.from_bytes(self.packet[4:8], 'little')
                    self.processPacket(packet_id, self.packet[8:])

                self.buffer = self.buffer[8:]

    def processPacket(self, packet_id, packet_data):
        raise NotImplementedError('processPacket not implemented')
