#!/usr/bin/python3
from io import BytesIO
from noxcryptlib import noxcrypt, types

import argparse
import os
import struct

parser = argparse.ArgumentParser(description='Nox script object extractor')
parser.add_argument('--output', '-o', required=True)
parser.add_argument('input')
args = parser.parse_args()

f = open(args.input, 'rb')
outp = open(args.output, 'wb')
tmp = BytesIO()

sig = f.read(0x4)
if sig != b'\xce\xfa\xde\xfa':
    f.seek(0, os.SEEK_SET)
    noxcrypt(f, tmp, 'map')
    f.close()
    f = tmp

f.seek(0, os.SEEK_SET)
sig = f.read(0x4)
assert sig == b'\xce\xfa\xde\xfa'

f.read(0x14)
while True:
    nlen = f.read(1)
    if len(nlen) == 0 or ord(nlen) == 0:
        break
    name = f.read(ord(nlen))
    if f.tell() % 8 != 0:
        f.seek((f.tell() + 7) & ~7)
    size = struct.unpack('<Q', f.read(8))[0]
    data = f.read(size)

    if name == b'ScriptObject\0':
        # skip number of scriptobjects, and length of each
        outp.write(data[6:])
        break

f.close()
outp.close()
