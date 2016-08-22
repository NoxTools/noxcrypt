#!/usr/bin/env python3
import argparse
import blowfish
import struct

keys = [
    0x0AB04D26A, 0x4DBE473C, 0x0AE6CE584, 0x0D4E2491D,
    0x0C682CC7, 0x0F511D537, 0x0B6E7920A, 0x264BC472,
    0x0FCB06F3D, 0x26C7CE4E, 0x649945F7, 0x0EAF67076,
    0x8FFDC4C3, 0x17ADF30C, 0x0C24A8DAC, 0x4A4522AE,
    0x65E334A, 0x5DD4422E, 0x0C9ACFE96, 0x0E2197A2E,
    0x1F3F0E75, 0x857C840B, 0x0B1A0E6B5, 0x14D418B1,
    0x595EF1F7, 0x0B246A7AA, 0x317E8041, 0x0CB9945F7,
    0x3D7390B4, 0x3A3140AE, 0x987CC51E, 0x0FE4A669A,
    0x1F284CFB, 0x790E7734, 0x0D9D7DD1, 0x4903FB93,
    0x0B195E6B7, 0x692B13E9, 0x0F78CD7D5, 0x720EA1E3,
    0x65C2253D, 0x832BF4E8, 0x0C45796A3, 0x769A3CF0,
    0x48A29A5C, 0x2096947B, 0x579D7328, 0x6488DC30,
    0x5661E53E, 0x0B148ADE7, 0x6857A3D6, 0x0A1D75B76,
    0x11E0E50A, 0x7BC7411F, 0x1956AE43, 0x5837A1E9,
    0x0B6FEA47B, 0x0A4AE235B, 0x71D1AA6E, 0x0AC4C6C4A,
    0x0BB834308, 0x4CCE994F, 0x900C099D, 0x80BA266D,
    0x9FD2A255, 0x6886D233, 0x80707757, 0x2CB6578A,
    0x0A7C6AE4D, 0x8DCE311A, 0x0D0B528BB, 0x792B7BA,
    0x8209F630, 0x53D63BB7, 0x5104A539, 0x0C70FE96A,
    0x2B9FFCFE, 0x9FE150FA, 0x68D4396C, 0x0BB3402BC,
    0x6514A727, 0x9E0E94CE, 0x992CC2F, 0x0C1B42904,
    0x99D44F02, 0x0F5E015E2, 0x5F8BA40F, 0x3D09A7C3,
    0x0D133BD51, 0x60137DFF, 0x55E37496, 0x69D16894,
    0x6AEB7B44, 0x0ADE4D9AC, 0x9CADE77E, 0x2E73E055,
    0x0D81AC011, 0x0E6E170FE, 0x0CC36F8F5, 0x0A9BC9DD7,
    0x2ADF856, 0x3850599B, 0x0FA700CC0, 0x381A749B,
    0x1D2AF767, 0x991A8914, 0x7FCD212B, 0x0DD6B3E7B,
    0x52088587, 0x52DFB738, 0x5D902E4A, 0x0A6A676B2,
    0x13E6F380, 0x0C9394093, 0x0D82B37D1, 0x902DA8C5,
    0x49256BD2, 0x553DC797, 0x0DC7F749B, 0x0E216EB76,
    0x0C8BE7E13, 0x46A05FFB, 0x0E2DBF0C2, 0x0B9AF815E,
    0x0A5CDF32A, 0x0D7AF9BBE, 0x0C4F119BB, 0x53C9B5FE,
    0x8E29FF1C, 0x2C5A8F85, 0x0F9343EF7, 0x8F249F8D,
    0x0F1142113, 0x4ED3D131, 0x31832DE9, 0x9E76DC9,
    0x46FAC8B0, 0x8FD4DD41, 0x70F773C1, 0x0E6CA7EBD,
    0x0E2B6A770, 0x85EF667, 0x415B7BC2, 0x0A93739AB,
    0x99630FBF, 0x7A49095C, 0x230DFE27, 0x0DFF6D40B,
    0x8F21632C, 0x86A1EF0B, 0x9AA3B61B, 0x3B032F82,
    0x0F8DB8B67, 0x5E8BE23, 0x98A761C5, 0x3B83F9FC,
    0x477652CC, 0x0B0E7BDF8, 0x0D9816067, 0x450FF993,
    0x55FBE657, 0x58EA1881, 0x98F7DD7, 0x0DF6178DF,
    0x9E3EBEAD, 0x589F41FF, 0x884075DF, 0x853EBAFF,
    0x3C1DBDF3, 0x0A816F615, 0x0D3736CE8, 0x5159BE97,
    0x0DE9A13C3, 0x0DD87D429, 0x41265C5, 0x0A9C293D,
    0x24791E3B, 0x0C5BC140A, 0x0C081E773, 0x84BF9830,
    0x76AFCC23, 0x0DCE83023, 0x22BF17AE, 0x0B21E97BC,
    0x15DF20EA, 0x0E04ADDF1, 0x93753E27, 0x8EFBE9F2,
    0x5216DF, 0x52C69FCA, 0x0D1F7077A, 0x87D377F9,
    0x7C8769F7, 0x0C0661264, 0x6BC5D1E2, 0x101A9E9F,
    0x0DB6579E0, 0x106BC5, 0x0C0BCBCF9, 0x2FC7C74C,
    0x0EF7AEE14, 0x0D520418E, 0x96173282, 0x16692BC1,
    0x32E866F2, 0x91BD8472, 0x84E70EEB, 0x235A37F7,
    0x53E1A002, 0x0D563E82D, 0x924498C6, 0x0BB6F66FB,
    0x0A9284529, 0x1641C97C, 0x168B7494, 0x35A2912D,
    0x61905335, 0x0D0B528BB, 0x792B7BA, 0x8209F630,
    0x53D63BB7, 0x5104A539, 0x0C70FE96A, 0x2B9FFCFE,
]

types = {
    'theme': 1,
    'soundset': 5,
    'thing': 7,
    'gamedata': 8,
    'modifier': 13,
    'map': 19,
    'monster': 23,
    'plr': 27,
    'save': 27,
}

parser = argparse.ArgumentParser(description='NoxCrypt tool')
parser.add_argument('--type', '-t', choices=types, required=True)
parser.add_argument('--encrypt', '-e', action='store_true')
parser.add_argument('--output', '-o', required=True)
parser.add_argument('input')
args = parser.parse_args()

idx = types[args.type]
def idx_to_key_bytes(idx):
    return b''.join([struct.pack('<I', keys[x]) for x in range(7 * idx, 7 * idx + 14)])

cipher = blowfish.Cipher(idx_to_key_bytes(idx))
inp = open(args.input, 'rb')
outp = open(args.output, 'wb')
while True:
    data = inp.read(4096)
    if len(data) == 0:
        break
    if len(data) % 8 != 0:
        print('Padding to 8-bytes')
        data += b'\x00' * (8 - (len(data) % 8))
    if args.encrypt:
        blocks = cipher.encrypt_ecb(data)
    else:
        blocks = cipher.decrypt_ecb(data)
    outp.write(b''.join(blocks))
