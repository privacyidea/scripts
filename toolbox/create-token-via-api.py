#!/opt/privacyidea/bin/python
from flask import Flask
from privacyidea.lib.token import init_token, get_tokens
from privacyidea.lib.user import User
import argparse
from flask_sqlalchemy import SQLAlchemy
from privacyidea.lib.utils import BASE58
from privacyidea.lib.crypto import generate_password
from privacyidea.app import create_app
import requests
import re
import sys
import urllib3

 
__doc__ = """
This scripts creates a tokentype via the API
It expects usernames from stdin
 
   create-token-via-api.py  
 
You can place the script in your scripts directory /etc/privacyidea/scripts/
 
Adapt it (like the TOKENTYPE and REALM) to your needs.
 
(c) 2020, Cornelius Kölbel <cornelius.koelbel@netknights.it>
 
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
TOKEN_TYPE = "registration"
API_USER = "super"
API_PASSWORD = "test"
REALM = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_auth_tok():
    r = requests.post('https://localhost/auth', verify=False,
                      data={"username": API_USER, "password": API_PASSWORD})
    authorization = r.json().get("result").get("value").get("token")
    return authorization


def create_token(username, realm, authorization):
    app = create_app(config_name="production",
                     config_file="/etc/privacyidea/pi.cfg",
                     silent=True)
 
    with app.app_context():

        params = {"type": TOKEN_TYPE, "genkey": 1}
        if username:
            params["user"] = username.strip()
            if realm:
                params["realm"] = realm
            r = requests.post('https://localhost/token/init', verify=False,
                              data=params,
                              headers={"Authorization": authorization})
            serial = r.json().get("detail").get("serial")
            return serial
 
 
parser = argparse.ArgumentParser()
parser.add_argument('infile', nargs='?', type=argparse.FileType('r'),
                    default=sys.stdin)
args = parser.parse_args()

auth_tok = get_auth_tok()

for user in args.infile:
    serial = create_token(user, REALM, auth_tok)
    print(serial)
