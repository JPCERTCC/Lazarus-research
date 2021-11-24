#!/usr/bin/env python
#
#
# Example:
# python blindingcan_rc4_post_decode.py "id=d3Ztd3lod2t0Tqf42ux9uv3FGH+Y3oAc2w==&bbs=HA==&tbl=&bbs_form="
#
#

import base64
import argparse
import sys
from struct import pack, unpack

parser = argparse.ArgumentParser(description="Blindingcan_RC4 POST decoder")
parser.add_argument("POST", help="POST data (without HTTP header)")
parser.add_argument('-k', '--key', action='store', dest='key', help="RC4 key")
args = parser.parse_args()

# RC4
def custom_rc4(data, key):
    x = 0
    box = list(range(256))
    for i in range(256):
        x = (x + int(box[i]) + int(key[i % len(key)])) % 256
        box[i], box[x] = box[x], box[i]

    x = 0
    for i in range(0xC00):
        i = i + 1
        x = (x + int(box[i % 256])) % 256
        wow_x = x
        box[i % 256], box[x] = box[x], box[i % 256]
        wow_y = i % 256

    x = wow_y
    y = wow_x
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr(char ^ box[(box[x] + box[y]) % 256]))

    return ''.join(out)


def main():
    sep = '&'

    data = args.POST

    if args.key:
       key = args.key

    field = data.split(sep)
    print("[+] {0} field(s) found in data".format(len(field)))

    post_data = {}
    for i in range(len(field)):
        value = field[i].split("=")

        if len(value[1]):
            base64_data = value[1]
            for i in range(len(value) - 2):
                base64_data = base64_data + "="
            post_data[value[0]] = base64_data

    if "id" in post_data:
        key = base64.b64decode(post_data["id"][:12])
        post_data["id"] = post_data["id"][12:]
        print("[+] found rc4 key: {0}".format(key))

    print(post_data)
    for k, v in post_data.items():
        decode_data = custom_rc4(base64.b64decode(v), key)
        print("[+] {0}: {1}".format(k, decode_data))


    print("[+] Done.")

if __name__ == "__main__":
    main()
