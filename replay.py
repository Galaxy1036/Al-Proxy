import os


class Replay:

    def __init__(self, dirname):
        self.dirname = dirname

        self.message_index_path = '{}/message.index'.format(self.dirname)

        if not os.path.isdir(self.dirname):
            self.init_directory()

        else:
            self.check_directory()

    def init_directory(self):
        os.makedirs(self.dirname)
        self.write_index()

    def check_directory(self):
        if not os.path.isfile(self.message_index_path):
            self.write_index()

    def write_index(self, index='0'):
        with open(self.message_index_path, 'w') as f:
            f.write(index)

    def increment_index(self, index):
        self.write_index(str(index + 1))

    def get_index(self):
        with open(self.message_index_path, 'r') as f:
            return int(f.read())

    def save_packet(self, packet_name, packet_data):
        index = self.get_index()

        with open('{}/{}-{}.bin'.format(self.dirname, index, packet_name), 'wb') as f:
            f.write(packet_data)

        self.increment_index(index)
