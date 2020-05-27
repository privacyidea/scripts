#!/opt/privacyidea/bin/python
from flask import Flask
from privacyidea.lib.token import init_token, get_tokens
from privacyidea.lib.user import User, get_user_list
from privacyidea.lib.realm import get_default_realm
import argparse
from flask_sqlalchemy import SQLAlchemy
from privacyidea.lib.utils import BASE58
from privacyidea.lib.crypto import generate_password
from privacyidea.app import create_app
import requests
import re
import sys
 
__doc__ = """
This scripts fetches all users that are known to privacyidea but which have
no token assigned.
 
   get-users-without-token.py [--realm <realm>] [--include-inactive]  
 
You can place the script in your scripts directory /etc/privacyidea/scripts/
  
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

def get_users(realm, include_inactive):
    app = create_app(config_name="production",
                     config_file="/etc/privacyidea/pi.cfg",
                     silent=True)
 
    with app.app_context():
        realm = realm or get_default_realm()
        params = {"realm": realm}
        ulist = get_user_list(params)
        active = None
        if include_inactive:
            active = True
        for user in ulist:
            user_obj = User(user.get("username"), realm, user.get("resolver"))
            toks = get_tokens(user=user_obj, active=active)
            if len(toks) == 0:
                print(user.get("username"))


parser = argparse.ArgumentParser()
parser.add_argument('infile', nargs='?', type=argparse.FileType('r'),
                    default=sys.stdin)
parser.add_argument("--include-inactive", dest="include_inactive",
                    action='store_true',
                    help="Also list users, who have inactive tokens")
parser.add_argument('--realm', dest='realm',
                    help="The realm of the user, to whom the token should be assigened.")
args = parser.parse_args()

get_users(realm=args.realm, include_inactive=args.include_inactive)