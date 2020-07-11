import os
import sys
import json
import argparse

from reader import BinaryReader


class PacketParser(BinaryReader):
    def __init__(self, data, definition):
        self.data = data
        self.indent = 0
        self.definition = definition
        self.function_dict = {
                              'BYTE': self.read_byte,
                              'SHORT': self.read_short,
                              'INT': self.read_int,
                              'LONG': self.read_long,
                              'STRING': self.read_string,
                              'OBFUSCATED_STRING': self.read_obfuscated_string
                             }

        super().__init__(data)

    def parse(self):
        if 'fields' in self.definition:
            for line in self.definition['fields']:
                self.parse_line(line)

    def log(self, value):
        print('{}{}'.format(' ' * self.indent, value))

    def parse_line(self, line):
        if 'type' in line:
            if line['type'] == 'DATA':
                if 'length' in line:
                    value = self.read(line['length'])

                else:
                    sys.exit('[*] Type "DATA" without length field')

            else:
                value = self.function_dict[line['type']]()

            if 'name' in line:
                self.log('{}: {}'.format(line['name'], value))

        else:
            dict_length_keys = set(line.keys()).intersection(['lengthType', 'length'])

            if dict_length_keys:
                if len(dict_length_keys) == 1:
                    if 'lengthType' in line:
                        if not line['lengthType'] in ('BYTE', 'INT', 'SHORT', 'LONG'):
                            sys.exit('[*] Wrong length type')

                        length = self.function_dict[line['lengthType']]()

                    else:
                        length = line['length']

                else:
                    sys.exit('[*] Too many length specified !')

                if 'components' not in line:
                    sys.exit('[*] Field with length but no components')

                if 'name' in line:
                    self.log('{}: ['.format(line['name']))

                else:
                    self.log('[')

                self.indent += 4

                for i in range(length):
                    self.log('{}:'.format(i + 1))
                    self.indent += 4

                    for subline in line['components']:
                        self.parse_line(subline)

                    self.indent -= 4

                self.indent -= 4

                self.log(']')

            else:
                sys.exit('[*] Unknown field, neither a type or components')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='A little tool that aim to parse packets using .json definitions')
    parser.add_argument('packet', help='The .bin packet to parse')
    parser.add_argument('-d', '--definition', help='The definition to use to parse the given packet', required=True)

    args = parser.parse_args()

    if os.path.isfile(args.packet):
        if os.path.isfile(args.definition):
            with open(args.packet, 'rb') as f:
                packet_data = f.read()

            with open(args.definition, 'r') as f:
                definition = json.load(f)

            PacketParser(packet_data, definition).parse()

        else:
            sys.exit('[*] Cannot find {} definition'.format(args.definition))

    else:
        sys.exit('[*] Cannot find {} packet'.format(args.packet))
