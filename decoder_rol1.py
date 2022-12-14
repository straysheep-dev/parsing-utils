#!/usr/bin/env python3

__description__ = 'ROL 1 byte decoder for oledump.py'
__author__ = 'Didier Stevens'
__version__ = '0.0.2'
__date__ = '2019/11/24'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2014/12/16: start
  2019/11/24: Python 3 fixes

Todo:
"""

def ParseNumber(number):
    if number.startswith('0x'):
        return int(number[2:], 16)
    else:
        return int(number)

class cROL1Decoder(cDecoderParent):
    name = 'ROL 1 byte decoder'

    def __init__(self, stream, options):
        self.stream = stream
        self.options = options
        if self.options.startswith('-k '):
            self.keyROL1 = ParseNumber(self.options[3:])
        else:
            self.keyROL1 = 0x01

    def Available(self):
        return self.keyROL1 != 0x08

    def Decode(self):
        if sys.version_info[0] > 2:
            decoded = bytes([(((c << self.keyROL1) | (c >> (8 - self.keyROL1))) & 0xFF) for c in self.stream])
        else:
            decoded = ''.join([chr(((ord(c) << self.keyROL1) | (ord(c) >> (8 - self.keyROL1))) & 0xFF) for c in self.stream])
        self.name = 'ROL 1 byte key 0x%02X' % self.keyROL1
        self.keyROL1 += 1
        return decoded

    def Name(self):
        return self.name

AddDecoder(cROL1Decoder)
