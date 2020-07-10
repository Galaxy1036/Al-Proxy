import os
import sys

from colorama import Fore
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from asn1crypto.x509 import Certificate


class RsaCrypto:
    def __init__(self):
        if os.path.isfile('private_key.pem'):
            if os.path.isfile('92700.der'):
                with open('private_key.pem') as f:
                    self.private_key = RSA.importKey(f.read())

                with open('92700.der', 'rb') as f:
                    cert = Certificate.load(f.read())
                    self.public_server_key = RSA.construct(
                        (
                            cert.public_key.native['public_key']['modulus'],
                            cert.public_key.native['public_key']['public_exponent']
                        )
                    )

            else:
                sys.exit('{}[x] Missing public server key, cannot continue'.format(Fore.RED))

        else:
            sys.exit('{}[x] Missing private key, cannot continue'.format(Fore.RED))

    def decrypt_client_packet(self, cipher):
        plain = PKCS1_v1_5.new(self.private_key).decrypt(cipher, None)

        if plain is not None:
            return plain

        else:
            raise ValueError('Cannot decrypt the given cipher')

    def encrypt_client_packet(self, plaintext):
        return PKCS1_v1_5.new(self.public_server_key).encrypt(plaintext)

    def decrypt_server_packet(self, cipher):
        raise NotImplementedError('Not implemented')

    def encrypt_server_packet(self, plaintext):
        raise NotImplementedError('Not implemented')
