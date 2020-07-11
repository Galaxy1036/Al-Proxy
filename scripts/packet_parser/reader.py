import struct

from io import BufferedReader, BytesIO


class BinaryReader(BufferedReader):
    def __init__(self, data):
        super().__init__(BytesIO(data))

    def read_byte(self):
        return int.from_bytes(self.read(1), 'little')

    def read_short(self):
        return int.from_bytes(self.read(2), 'little')

    def read_float16(self):
        return struct.unpack('<e', self.read(2))[0]  # binary16

    def read_int24(self):
        return int.from_bytes(self.read(3), 'little')

    def read_int(self):
        return int.from_bytes(self.read(4), 'little')

    def read_long(self):
        return int.from_bytes(self.read(8), 'little')

    def read_string(self):
        return self.read(self.read_short()).decode('utf-8')

    def read_obfuscated_string(self):
        seed = self.read_int()
        obfuscated = self.read(self.read_short())

        output = []

        for char in obfuscated:
            seed, computed = self.compute_seed(seed)
            output.append(computed ^ char)

        return bytes(output).decode('utf-8')

    # Custom lehmer random number generator implementation used for obfuscation purpose
    def compute_seed(self, seed):
        div = int((seed ^ 0x75BD924) / 127773)
        rem = (seed ^ 0x75BD924) % 127773

        result = 16807 * rem - 2836 * div

        if result < 0:
            result += 0x7FFFFFFF

        new_seed = result ^ 0x75BD924

        result = min((result * 4.6566e-10) * 256, 255)

        return new_seed, int(result)
