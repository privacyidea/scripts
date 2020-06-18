#!/usr/bin/env python
import argparse
import sys
import requests
import uuid
from base64 import b64encode

# Do not change Boom URL
URL = "https://direct-api.apps.boomcomms.com/v1/sms1"
DEFAULT_CONFIG = "/etc/privacyidea/boomalert.cfg"

parser = argparse.ArgumentParser(description='Send SMS via Boom Alert.')
parser.add_argument('--config', '-c', help="Specify the config file.",
                    default=DEFAULT_CONFIG)
parser.add_argument('--generate', '-g', help="Generate a config file.",
                    action="store_true")
parser.add_argument('phones', metavar='N', type=str, nargs='?',
                    help='Phone numbers to send SMS to.')
parser.add_argument('infile', nargs='?', type=argparse.FileType('r'),
                    default=sys.stdin)
args = parser.parse_args()


def generate_config():
    print("""USERNAME = Your Username
PASSWORD = Your Password
LICENSE_KEY = Your Licensekey
campaign_name =
custom_parameter =
""")
    sys.exit(0)


if args.generate:
    generate_config()

if not args.phones:
    print("You need to specify a phone number.")
    sys.exit(1)

config = {}
with open(args.config) as file:
    lines = file.readlines()
    for line in lines:
        if line:
            try:
                k, v = line.split("=", 2)
                config[k.strip()] = v.strip()
            except ValueError:
                print("Cann not unpack {0!s}.".format(line))

unique_id = "privacyidea_{0!s}".format(uuid.uuid1())

message = ""
for line in args.infile:
    message += line

headers = {"accept": "application/json",
           "X-License-Key": config.get("LICENSE_KEY"),
           "Content-Type": "application/json"}

json_body = {"from": "privacyIDEA",
             "message_content": message,
             "recipient_address": [{"number": phone} for phone in args.phones],
             "priority": False,
             "unique_identifier": unique_id}
if "campaign_name" in config:
    json_body["campaign_name"] = config.get("campaign_name")
if "custom_parameter" in config:
    json_body["custom_parameter"] = config.get("custom_parameter")

r = requests.post(URL, headers=headers, json=json_body,
                  auth=(config.get("USERNAME"), config.get("PASSWORD")))
if r.status_code != 200:
    # return an error, which will also be logged as return code in privacyIDEA
    sys.exit(r.status_code)
