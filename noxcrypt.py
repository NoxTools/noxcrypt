#!/usr/bin/env python3
from noxcryptlib import noxcrypt, types

import argparse

parser = argparse.ArgumentParser(description='NoxCrypt tool')
parser.add_argument('--type', '-t', choices=types, required=True)
parser.add_argument('--encrypt', '-e', action='store_true')
parser.add_argument('--output', '-o', required=True)
parser.add_argument('input')
args = parser.parse_args()

inp = open(args.input, 'rb')
outp = open(args.output, 'wb')

noxcrypt(inp, outp, args.type, args.encrypt)

inp.close()
outp.close()
