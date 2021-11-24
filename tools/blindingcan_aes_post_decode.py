#!/usr/bin/env python
#
#
# Example:
# python blindingcan_aes_post_decode.py packet-data
#
#

import base64
import argparse
import sys, os, re

try:
    from Crypto.Cipher import AES
except ImportError:
    print('[!] Please install pycrypto.')
    sys.exit(1)

parser = argparse.ArgumentParser(description="Blindingcan_AES POST decoder")
parser.add_argument("POST", help="POST data (with HTTP header)")
parser.add_argument('-k', '--key', action='store', dest='key', help="AES key")
args = parser.parse_args()


POST_VALUE = ["tname=", "blogdata=", "content=", "thesis=", "method=", "bbs=", "level=", "maincode=", "tab=", "idx=", "tb=", "isbn=", "entry=", "doc=", "category=", "articles=", "portal=", "notice=", "product=", "themes=", "manual=", "parent=", "slide=", "vacon=", "tag=", "tistory=", "property=", "course=", "plugin="]

# default AES key
KEY = "RC2zWLyG50fPIPkQ"


# AES
def aes_dec(data, key):
    cipher = AES.new(key[:16], AES.MODE_CBC, "\x00"*16)
    decrypt_data = cipher.decrypt(data)

    return decrypt_data


def main():
    keys = []
    if args.key:
        keys.append(args.key)

    keys.append(KEY)

    send_data = []
    rensponse_data = []
    join_data = []
    data_flag = 0
    with open(args.POST, "r") as f:
        for line in f:
            # parse response data
            if "Transfer-Encoding" in line:
                data_flag = 1
                continue
            if "POST" in line or re.match("^0\n", line):
                for b64 in "".join(join_data).split("=="):
                    if len(b64) > 0:
                        try:
                            if re.match("[a-zA-Z0-9]{16}", base64.b64decode(b64 + "==")):
                                keys.append(base64.b64decode(b64 + "=="))
                                print("[+] get AES key: {0}".format(base64.b64decode(b64 + "==")))
                            else:
                                rensponse_data.append(b64 + "==")
                        except:
                            pass
                data_flag = 0
                join_data = []
                continue

            if data_flag and len(line) > 5:
                join_data.append(line.replace(" ", "+").strip())

            # parse send data
            for vul in POST_VALUE:
                if vul in line:
                    b64_data = line.replace(vul, "").replace("HTTP/1.1 200 OK", "").strip()
                    decode_data = base64.b64decode(b64_data)
                    if re.match(".+@[0-9]{6}", decode_data):
                        key = decode_data.split("@")[0]
                        keys.append(key)
                        print("[+] get AES key: {0}".format(key))
                    else:
                        for b64 in b64_data.split("=="):
                            if len(b64) > 0:
                                try:
                                    if re.match("[a-zA-Z0-9]{16}", base64.b64decode(b64 + "==")):
                                        keys.append(base64.b64decode(b64 + "=="))
                                        print("[+] get AES key: {0}".format(base64.b64decode(b64 + "==")))
                                    else:
                                        send_data.append(b64 + "==")
                                except:
                                    pass

    # password change word
    word_keys = []
    for key in keys:
        word_key = ""
        for s in key:
            word_key = word_key + s + "\x00"
        word_keys.append(word_key)

    # decode send data
    i = 0
    for enc_data in send_data:
        if len(enc_data) > 16:
            for word_key in word_keys:
                dec_data = aes_dec(base64.b64decode(enc_data), word_key)
                if b"\x00\x00\x00" in dec_data:
                    break
        else:
            dec_data = base64.b64decode(enc_data)
        with open(args.POST + "-send" + str(i) + ".data", "wb") as f:
            f.write(dec_data)
        i += 1

    # decode response data
    i = 0
    for enc_data in rensponse_data:
        if len(enc_data) > 16:
            for word_key in word_keys:
                dec_data = aes_dec(base64.b64decode(enc_data), word_key)
                if b"\x00\x00\x00" in dec_data:
                    break
        else:
            dec_data = base64.b64decode(enc_data)
        with open(args.POST + "-rensponse" + str(i) + ".data", "wb") as f:
            f.write(dec_data)
        i += 1

    print("[+] Done.")

if __name__ == "__main__":
    main()
