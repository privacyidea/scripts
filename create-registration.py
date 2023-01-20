#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import requests
import re
import sys
 
__doc__ = """
This scripts creates a registration token for a given user via the REST API.

This is a script that can be called by the privacyIDEA script handler.
 
it takes the arguments
 
   create-registration.py --user <existing user> --realm <original_realm>
 
 
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
REMOTE_TOKEN = "registration"
REMOTE_SERVER = "https://localhost"
VERIFY_TLS = False


def create_token(username, realm):
    # Set global values
    params = { "genkey": 1 }
    params["user"] = username
    params["realm"] = realm
    params["type"] = REMOTE_TOKEN
    r = requests.post('{0!s}/auth'.format(REMOTE_SERVER), verify=VERIFY_TLS,
                      data={"username": API_USER, "password": API_PASSWORD})
    authorization = r.json().get("result").get("value").get("token")
    r = requests.post('{0!s}/token/init'.format(REMOTE_SERVER), verify=VERIFY_TLS,
                      data=params,
                      headers={"Authorization": authorization})
    serial = r.json().get("detail").get("serial")
    regcode = r.json().get("detail").get("registrationcode")
    return serial, regcode
 
 
parser = argparse.ArgumentParser()
parser.add_argument('--user', dest='username')
parser.add_argument('--realm', dest='realm')
args = parser.parse_args()

serial, regcode = create_token(args.username, args.realm)
print(serial)
print(regcode)