#!/opt/privacyidea/bin/python
from flask import Flask
from privacyidea.lib.token import get_tokens
from privacyidea.lib.user import User
import argparse
from flask_sqlalchemy import SQLAlchemy
from privacyidea.app import create_app
import re
import sys
 
__doc__ = """
This script resets the failcounter of all remote tokens 
after a successful authentication.

- given that the remote tokens are located locally!
 
This is a script that can be called by the privacyIDEA script handler.
 
it takes the arguments
 
   reset-failcounter.py --user <user> --realm <realm>
 
 You can place the script in your scripts directory /etc/privacyidea/scripts/
and use it in the script event handler.
 
Adapt it (like the TOKENTYPE and REALM) to your needs.
 
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


def reset_failcounter(username, realm):
    """
    find all remote tokens of a user and reset the failcounters of the linked tokens.
    """
    app = create_app(config_name="production",
                     config_file="/etc/privacyidea/pi.cfg",
                     silent=True)
 
    with (app.app_context()):
        # get all remote tokens of the user
        toks = get_tokens(tokentype="remote", user=User(username, realm))
        for tok in toks:
            # Reset this own failcounter
            tok.set_failcount(0)
            tok.save()
            r_serial = tok.get_tokeninfo("remote.serial")
            # Find the linked token
            r_toks = get_tokens(serial=r_serial)
            if r_toks:
                linked_tok = r_toks[0]
                linked_tok.set_failcount(0)
                linked_tok.save()
                print(f"Reset failcounter of remote token {tok.get_serial()} and linked token {r_serial}")

 
parser = argparse.ArgumentParser()
parser.add_argument('--user', dest='user')
parser.add_argument('--realm', dest='realm')
args = parser.parse_args()

reset_failcounter(args.user, args.realm)
