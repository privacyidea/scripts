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
 
__doc__ = """
This scripts creates a spass token for a user in RealmA and
a remote token for user in RealmB, that points ot the user in RealmA.
 
This is a script that can be called by the privacyIDEA script handler.
 
it takes the arguments
 
   create-remote-and-spass.py --user <existing user> --realm <original_realm>
 
 
You can place the script in your scripts directory /etc/privacyidea/scripts/
and use it in the script event handler.
 
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
#LOCAL_TOKEN = "remote"
LOCAL_TOKEN = "registration"
CREATE_LOCAL_TOKEN_VIA_API = True
API_USER = "super"
API_PASSWORD = "test"
REMOTE_TOKEN = "spass"
REMOTE_REALM = "remoterealm"
REMOTE_SERVER = "https://localhost"
# List of regex of users to exclude
EXCLUCDE_USERS = [".*@.*"]


def create_token(username, realm):
    app = create_app(config_name="production",
                     config_file="/etc/privacyidea/pi.cfg",
                     silent=True)
 
    with app.app_context():
        # Set global values
        params = {"type": LOCAL_TOKEN}
        if username:
            user = User(username, realm)
        else:
            user = User()
        
        if LOCAL_TOKEN == "remote":
            # For a remote token, we need some additional parameters
            params["remote.server"] = REMOTE_SERVER
            params["remote.user"] = username
            params["remote.realm"] = REMOTE_REALM
            params_remote = {"type": REMOTE_TOKEN}
            remote_user = User(username, REMOTE_REALM)
            remote_token = init_token(params_remote, remote_user)
        else:
            # For other tokens, we need genkey=1
            params["genkey"] = 1
        
        if CREATE_LOCAL_TOKEN_VIA_API:
            params["user"] = username
            params["realm"] = realm
            r = requests.post('https://localhost/auth', verify=False,
                              data={"username": API_USER, "password": API_PASSWORD})
            authorization = r.json().get("result").get("value").get("token")
            r = requests.post('https://localhost/token/init', verify=False,
                              data=params,
                              headers={"Authorization": authorization})
            serial = r.json().get("detail").get("serial")
        else:
            tok = init_token(params, user)
            serial = tok.token.serial
        return serial
 
 
parser = argparse.ArgumentParser()
parser.add_argument('--user', dest='username')
parser.add_argument('--realm', dest='realm')
parser.add_argument('--logged_in_realm', dest='lrealm')
parser.add_argument('--logged_in_user', dest='tuser')
args = parser.parse_args()

for exclude_re in EXCLUCDE_USERS:
    if re.match(exclude_re, args.username):
        print("We do not enroll token for user {0!s}.".format(args.username))
        sys.exit(0)

serial = create_token(args.username, args.realm)
print(serial)