#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import requests
import re
import sys
 
__doc__ = """
This scripts deletes all TOTP tokens of a given user

This is a script that can be called by the privacyIDEA script handler.
 
it takes the arguments
 
   delete-totp.py --user <existing user> --realm <original_realm>
 
 
You can place the script in your scripts directory /etc/privacyidea/scripts/
and use it in the script event handler.
 
Adapt it (like the TOKENTYPE) to your needs.
 
(c) 2021, Cornelius Kölbel <cornelius.koelbel@netknights.it>
 
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 3 as
    published by the Free Software Foundation.
 
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 
    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""

# You may change this
API_USER = "super"
API_PASSWORD = "test"
TOKENTYPE = "totp"
REMOTE_SERVER = "https://localhost"
VERIFY_TLS = False


def delete_token(username, realm):
    serials = []
    if not username:
        raise Exception("No username specified!")
    params = {"user": username}
    params["realm"] = realm
    params["type"] = TOKENTYPE
    r = requests.post('{0!s}/auth'.format(REMOTE_SERVER), verify=VERIFY_TLS,
                      data={"username": API_USER, "password": API_PASSWORD})
    authorization = r.json().get("result").get("value").get("token")
    r = requests.get('{0!s}/token/'.format(REMOTE_SERVER), verify=VERIFY_TLS,
                     data=params,
                     headers={"Authorization": authorization})
    result_value = r.json().get("result").get("value")
    if result_value.get("count") > 15:
        # FIXME: We would have to take care, if the user had more than 15 TOTP tokens!
        raise Exception("This script is bullocks. The user has more than 15 TOTP tokens.")
    for tok in result_value.get("tokens"):
        serial = tok.get("serial")
        r = requests.delete('{0!s}/token/{1!s}'.format(REMOTE_SERVER, serial), verify=VERIFY_TLS,
                            headers={"Authorization": authorization})
        if r.status_code == 200:
            serials.append(serial)
    return serials
 
 
parser = argparse.ArgumentParser()
parser.add_argument('--user', dest='username')
parser.add_argument('--realm', dest='realm')
args = parser.parse_args()

serials = delete_token(args.username, args.realm)
for serial in serials:
    print(serial)