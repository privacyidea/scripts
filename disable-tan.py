#!/opt/privacyidea/bin/python
from flask import Flask
from privacyidea.lib.token import get_tokens, enable_token
from privacyidea.lib.user import User
import argparse
from privacyidea.app import create_app
import sys

__doc__ = """
This script is supposed to be called by the event handler after a token is created.

In this case the user and realm parameter exists.
This script then checks if the user has a TAN token assigned and disables all TAN tokens.

   disable-tan.py --user <username> --realm <realm>

You can place the script in your scripts directory /etc/privacyidea/scripts/
and use it in the script event handler.

Configure your script handler like:

event: token_init
position: Post
conditions: 
 * tokentype
action:
 * background: background
 * user: True
 * realm: True
 * sync_to_database: True

Adapt it (like the DISABLE_TOKENTYPES) to your needs.

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
DISABLE_TOKENTYPES = ["tan"]
CONFIG_FILE = "/etc/privacyidea/pi.cfg"


def disable_tokens(user, realm):
    app = create_app(config_name="production",
                     config_file=CONFIG_FILE,
                     silent=True)

    with app.app_context():
        user_obj = User(login=user, realm=realm)
        tokens = get_tokens(user=user_obj, active=True)
        for token in tokens:
            if token.get_type() in DISABLE_TOKENTYPES:
                enable_token(token.token.serial, False)
                print("Disabled {0!s} token {1!s} for user {2!s}.".format(token.get_type(), token.token.serial, user))

parser = argparse.ArgumentParser()
parser.add_argument('--user', dest='user')
parser.add_argument('--realm', dest='realm')
args = parser.parse_args()
disable_tokens(args.user, args.realm)
