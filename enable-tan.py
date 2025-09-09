#!/opt/privacyidea/bin/python
from flask import Flask
from privacyidea.lib.token import get_token_owner, enable_token, get_tokens
from privacyidea.lib.user import User
import argparse
from privacyidea.app import create_app
import sys

__doc__ = """
This script is supposed to be called by the event handler before a token is deleted.

In this case the seiral number of the token exists.
This script then checks, if the token owner has a TAN token assigned and enables this tan token.

   enable-tan.py --serial <serialnumber>

You can place the script in your scripts directory /etc/privacyidea/scripts/
and use it in the script event handler.

Configure your script handler like:

event: token_disable, token_delete
position: Pre
conditions: 
 * tokentype
action:
 * background: No
 * serial: True
 * sync_to_database: True

Adapt it (like the ENABLE_TOKENTYPES) to your needs.

(c) 2025, Cornelius Kölbel <cornelius.koelbel@netknights.it>

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

# This is a list of users to create remote tokens for
ENABLE_TOKENTYPES = ["tan"]
CONFIG_FILE = "/etc/privacyidea/pi.cfg"


def enable_tokens(serial):
    app = create_app(config_name="production",
                     config_file=CONFIG_FILE,
                     silent=True)

    with app.app_context():
        user_obj = get_token_owner(serial)
        tokens = get_tokens(user=user_obj, active=False)
        for token in tokens:
            if token.get_type() in ENABLE_TOKENTYPES:
                enable_token(token.token.serial, True)
                print("Enabled {0!s} token {1!s} for user {2!s}.".format(token.get_type(), token.token.serial,
                                                                         user_obj.login))

parser = argparse.ArgumentParser()
parser.add_argument('--serial', dest='serial')
args = parser.parse_args()
enable_tokens(args.serial)
