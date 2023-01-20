#!/opt/privacyidea/bin/python
from flask import Flask
from privacyidea.lib.token import get_tokens, enable_token
from privacyidea.lib.tokenclass import ROLLOUTSTATE
from privacyidea.lib.user import User
import argparse
from flask_sqlalchemy import SQLAlchemy
from privacyidea.app import create_app
import datetime

__doc__ = """
This scripts either disables or deletes all existing SMS tokens for a user, 
e.g. if the user gets a new token enrolled.

This is a script that can be called by the privacyIDEA script handler.

it takes the arguments

   delete-or-disable-token.py --user <existing user> --realm <user-realm>

You can place the script in your scripts directory /etc/privacyidea/scripts/
and use it in the script event handler.

Adapt it (like the TOKENTYPE and ACTION) to your needs.

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

# This is a list of tokentypes to delete
TOKENTYPES_TO_DELETE = ["sms"]
ACTIVE = True
ACTION = "disable"
#ACTION = "delete"
LOGFILE = "/var/log/privacyidea/disabled-tokens.log"
ROLLOUT_STATE = None
#ROLLOUT_STATE = ROLLOUTSTATE.VERIFYPENDING


def modify_token(username, realm, ttypes):
    app = create_app(config_name="production",
                     config_file="/etc/privacyidea/pi.cfg",
                     silent=True)

    with app.app_context():
        user_obj = User(username, realm)
        if user_obj:
            for ttype in ttypes:
                # Get all active tokens of this types from this user
                toks = get_tokens(user=user_obj, tokentype=ttype, active=ACTIVE, rollout_state=ROLLOUT_STATE)
                # Delete all SMS tokens.
                for tok_obj in toks:
                    serial = tok_obj.token.serial
                    if ACTION == "delete":
                        tok_obj.delete_token()
                    else:
                        enable_token(serial, False)
                    with open(LOGFILE, "a") as f:
                        f.write(u"{0!s}, {1!s}, {2!s}, {3!s}, {4!s}\n".format(
                            datetime.datetime.now().strftime("%Y-%m-%dT%H:%M"),
                            args.username, args.realm, ACTION, serial))


parser = argparse.ArgumentParser()
parser.add_argument('--user', dest='username')
parser.add_argument('--realm', dest='realm')
args = parser.parse_args()

modify_token(args.username, args.realm, TOKENTYPES_TO_DELETE)

