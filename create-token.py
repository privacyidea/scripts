#!/opt/privacyidea/bin/python
from flask import Flask
from privacyidea.lib.token import init_token, get_tokens
from privacyidea.lib.user import User
import argparse
from flask_sqlalchemy import SQLAlchemy
from privacyidea.lib.utils import BASE58
from privacyidea.lib.crypto import generate_password
from privacyidea.app import create_app

__doc__ = """
This scripts create new tokens for a given user.

This is a script that can be called by the privacyIDEA script handler.

it takes the arguments

   create-token.py --user <existing user> --serial <existing serial>

It can also run to create multiple tokens:

   create-token.py --user <existing user> --count 100

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

TOKENTYPE = "pw"
PW_LEN = 10
REALM = "testfoo"


def create_token(serial, username):
    app = create_app(config_name="production",
                     config_file="/etc/privacyidea/pi.cfg",
                     silent=True)

    with app.app_context():
        # Set global values
        params = {"type": TOKENTYPE}
        if username:
            user = User(username, REALM)
        else:
            user = User()
        if serial:
            params["serial"] = serial
        password = generate_password(size=PW_LEN, characters=BASE58)
        params["otplen"] = PW_LEN
        params["otpkey"] = password
        tok = init_token(params, user)
        return tok.token.serial, password


parser = argparse.ArgumentParser()
parser.add_argument('--serial', dest='serial')
parser.add_argument('--user', dest='username')
parser.add_argument('--count', dest='count')
args = parser.parse_args()

count = int(args.count or 1)
for i in range(0, count):
    serial, password = create_token(args.serial, args.username)
    print("{0!s}: {1!s}".format(serial, password))

