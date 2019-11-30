#!/opt/privacyidea/bin/python
from flask import Flask
from privacyidea.lib.token import unassign_token, assign_token
from privacyidea.lib.user import User
import argparse

__doc__ = """
This is a script that can be called by the privacyIDEA script handler.

it takes the arguments

   reassign-token.py --user <existing user> --serial <existing serial>
   
You can place the script in your scripts directory /etc/privacyidea/scripts/
and use it in the script event handler.

Adapt it (like the NEW_REALM) to your needs.

(c) 2019, Cornelius Kölbel <cornelius.koelbel@netknights.it>

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

NEW_REALM = "new_realm"


def reassign_token(serial, username):
    app = Flask(__name__, static_folder="static",
                template_folder="static/templates")
    app.config.from_pyfile("/etc/privacyidea/pi.cfg", silent=True)

    with app.app_context():
        # Set global values
        unassign_token(serial)
        assign_token(serial, User(username, NEW_REALM))


parser = argparse.ArgumentParser()
parser.add_argument('--serial', dest='serial')
parser.add_argument('--user', dest='username')
args = parser.parse_args()

# reassign the token to a new realm
if args.serial and args.username:
    reassign_token(args.serial, args.username)
