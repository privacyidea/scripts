#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# (c) Cornelius Kölbel
# Info: http://www.privacyidea.org

from __future__ import print_function
import argparse
import re
import sys
try:
    from Crypto.Cipher import AES, DES
except ImportError:
    print("This tool needs pycryptodome. Please install it in your virtualenv.")
    sys.exit(1)
import binascii

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", help="LDIF export file.", required=True)

args = parser.parse_args()

all_tokens = []
current_token = {}
aes_key = "encryptionkey"
des_key = "encryoptionkey"

with open(args.file, 'r') as f:
    for line in f:
        if re.match("objectclass: SccDesAuthenticator.*", line):
            current_token = {}
        if re.match("sccAuthenticatorId", line):
            m = re.match("sccAuthenticatorId:(.*)$", line)
            serial = m.group(1).strip()
            current_token["serial"] = serial

        if re.match("sccTokenData", line):
            # First, find the encryption key
            m = re.search(r"sccKey=\((.*?)\).*", line)
            if m:
                seed = m.group(1)
                algo, data = seed.split(":")
                if algo.lower() == "aes":
                    aes = AES.new(aes_key, AES.MODE_ECB)
                    d = aes.decrypt(binascii.unhexlify(data))
                    current_token["seed"] = d.strip("\x00")

                elif algo.lower() == "des":
                    des = DES.new(des_key)
                    d = des.decrypt(binascii.unhexlify(data))
                    current_token["seed"] = d.strip("\x00")
            else:
                sys.stderr.write("Could not find key for token! {0}\n".format(line))

            if "seed" in current_token:
                # Then find the counter
                m = re.search(r"sccSeq=\((.*?)\).*", line)
                if m:
                    counter = m.group(1)
                    algo, data = counter.split(":")
                    if algo.lower() == "des":
                        des = DES.new(des_key)
                        d = des.decrypt(binascii.unhexlify(data))
                        current_token["counter"] = d.strip("\x00")

        if "serial" in current_token and "seed" in current_token:
            all_tokens.append(current_token)
            current_token = {}


for token in all_tokens:
    print("{0!s}, {1!s}, {2!s}".format(token.get("serial"), token.get("seed"), token.get("counter", 0)))
