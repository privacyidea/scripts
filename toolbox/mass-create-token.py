#!/opt/privacyidea/bin/python
from flask import Flask
from privacyidea.lib.user import User, create_user
from privacyidea.lib.error import TokenAdminError, UserError, ResourceNotFoundError
import argparse
from flask_sqlalchemy import SQLAlchemy
from privacyidea.app import create_app
import requests
import re
import sys
import urllib3

 
__doc__ = """
This scripts creates a user if necessary and then creates a token for
this uses.
 
The script takes a CSV file

   mass-create-token.py --resolver <name> --realm <name> --tokentype <toktype> < tokens.csv

The CSV file should look like this:

username, email, givenname, surname, pin

Adapt it to your needs.
 
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

API_USER = "massenroll"
API_PASSWORD = "changeme"


def create_token(resolver, realm, tokentype, username, email, givenname, surname, pin):
    app = create_app(config_name="production",
                     config_file="/etc/privacyidea/pi.cfg",
                     silent=True)

    with app.app_context():
        # User operations
        try:
            print("+ Processing user {0!s} in {1!s}/{2!s}.".format(username, resolver, realm))
            user_obj = User(username, realm, resolver=resolver)
        except UserError as err:
            sys.stderr.write(" +-- Failed finding user: {0!s}.\n".format(err))
            return

        if not user_obj.exist():
            print(" +- Creating user {0!s} in {1!s}/{2!s}.".format(username, resolver, realm))
            try:
                create_user(resolver, {"username": username,
                                       "email": email,
                                       "givenname": givenname,
                                       "surname": surname}, password="")
            except UserError as err:
                sys.stderr.write(" +-- Failed to create user: {0!s}.\n".format(err))
                return
            except Exception as err:
                sys.stderr.write(" +-- Failed to create user: {0!s}.\n".format(err))
                return

        # Token operations
        try:
            params = {}
            params["user"] = username
            params["realm"] = realm
            params["type"] = tokentype
            params["genkey"] = 1
            params["pin"] = pin
            r = requests.post('https://localhost/auth', verify=False,
                              data={"username": API_USER, "password": API_PASSWORD})
            authorization = r.json().get("result").get("value").get("token")
            r = requests.post('https://localhost/token/init', verify=False,
                              data=params,
                              headers={"Authorization": authorization})
            result = r.json().get("result")
            detail = r.json().get("detail")
            if not result.get("status"):
                sys.stderr.write(" +-- Failed to create token: {0!s}\n".format(result.get("error", {}).get("message")))
            if result.get("value"):
                print(" +-- Created token {0!s}.".format(detail.get("serial")))
        except Exception as err:
            sys.stderr.write(" +-- Failed to communicated to privacyIDEA: {0!s}\n".format(err))


parser = argparse.ArgumentParser()
parser.add_argument('--resolver', dest='resolver', required=True,
                    help="The resolver, in which the user should be created.")
parser.add_argument('--realm', dest='realm', required=True,
                    help="The realm of the user, to whom the token should be assigened.")
parser.add_argument('--tokentype', dest='tokentype', required=True,
                    help="The type of the token to create, like 'registration'.")
parser.add_argument("--disablewarn", dest="disablewarn",
                    action='store_true',
                    help="Suppress insecure HTTPS warning.")
args = parser.parse_args()
if args.disablewarn:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

i = 0
for line in sys.stdin:
    i += 1
    try:
        username, email, givenname, surname, pin = [x.strip() for x in line.split(",")]
        create_token(args.resolver, args.realm, args.tokentype,
                     username, email, givenname, surname, pin)
    except ValueError:
        sys.stderr.write("Malformed line {0!s}. Probably wrong number of columns.\n".format(i))



