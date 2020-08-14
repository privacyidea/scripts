#!/opt/privacyidea/bin/python
from flask import Flask
from privacyidea.lib.error import TokenAdminError, UserError, ResourceNotFoundError
from privacyidea.lib.token import assign_token, init_token
from privacyidea.lib.user import User, create_user
import argparse
from flask_sqlalchemy import SQLAlchemy
from privacyidea.app import create_app
import sys
import urllib3
import datetime


__doc__ = """
This script is ment to run at the command line. It

 * creates or updates a user in the configured resolver 
 * assigns an existing token or enrolls a registration token
   (and sets a PIN)
 * and create a RADIUS token with the given validity period
 
The script takes a CSV file

   create-user-assign-token.py --resolver <name> --realm <name> < tokens.csv

The CSV file should look like this:

   username, email, givenname, surname, hard/soft, attribute1, attribute2, pin, serial, validity period

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

# Change this to your needs:
ATTRIBUTES = ["attribute1", "attribute2"]
TOKEN_TYPE = "registration"
API_USER = "super"
API_PASSWORD = "test"
TOKENINFO = {"source": "scriptsource/T",
             "imported": datetime.datetime.now().strftime("%Y-%m-%dT%H:%M")}
HARDWARE = "H"
SOFTWARE = "S"


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_auth_tok():
    r = requests.post('https://localhost/auth', verify=False,
                      data={"username": API_USER, "password": API_PASSWORD})
    authorization = r.json().get("result").get("value").get("token")
    return authorization


def assign_user(resolver, realm, username, email, givenname, surname, serial, pin, attr1, attr2, validity, hard_or_soft):
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
            # Create new user
            print(" +- Creating user {0!s} in {1!s}/{2!s}.".format(username, resolver, realm))
            try:
                create_user(resolver, {"username": username,
                                       "email": email,
                                       "givenname": givenname,
                                       "surname": surname,
                                       ATTRIBUTES[0]: attr1,
                                       ATTRIBUTES[1]: attr2}, password="")
                user_obj = User(username, realm, resolver=resolver)
            except UserError as err:
                sys.stderr.write("+-- Failed to create user: {0!s}.\n".format(err))
                return
            except Exception as err:
                sys.stderr.write("+-- Failed to create user: {0!s}.\n".format(err))
                return
        else:
            # Update existing user
            print(" +- Updating user {0!s} in {1!s}/{2!s}.".format(username, resolver, realm))
            user_obj.update_user_info({"email": email,
                                       "givenname": givenname,
                                       "surname": surname,
                                       ATTRIBUTES[0]: attr1,
                                       ATTRIBUTES[1]: attr2})

        # Token operations

        ## Assign token or create registration code
        if hard_or_soft.strip().upper() == HARDWARE:
            if serial:
                # Assign an existing token
                try:
                    print(" +- Processing token {0!s}".format(serial))
                    t = assign_token(serial, user_obj, pin)
                    print(" +-- Assigned token to user {0!s}.".format(user_obj))
                except TokenAdminError as err:
                    sys.stderr.write(" +-- Failed assigning token {0!s}: {1!s}.\n".format(serial, err))
                except ResourceNotFoundError as err:
                    sys.stderr.write(" +-- Failed assigning token {0!s}: {1!s}.\n".format(serial, err))
            else:
                sys.stderr.write("+-- User {0!s} is supposed to get a hardware token, but no serial defined!".format(user_obj))
        elif hard_or_soft.strip().upper() == SOFTWARE:
            # Create a registration code, since no serial number is given
            print(" +- Creating token of type {0!s}.".format(TOKEN_TYPE))
            params = {"type": TOKEN_TYPE,
                      "genkey": 1,
                      "user": user_obj.loginname,
                      "realm": user_obj.realm}
            r = requests.post('https://localhost/token/init', verify=False,
                              data=params,
                              headers={"Authorization": get_auth_tok()})
            if not r.json().get("result").get("status"):
                sys.stderr.write(" +-- Failed to create token for user {0!s}.".format(user_obj))
        else:
            sys.stderr.write("+-- Unknown Hard/Soft specifier for user {0!s}: {1!s}".format(user_obj, hard_or_soft))

        # Create RADIUS token with validity period
        print(" +- Creating RADIUS token for user {0!s}.".format(user_obj))
        tok = init_token({"type": "radius",
                          "radius.identifier": RADIUS_IDENTIFIER,
                          "radius.user": user_obj.loginname},
                         user=user_obj)
        tok.add_tokeninf(TOKENINFO)
        validity_end = datetime.datetime.now() + datetime.timedelta(int(validity))
        tok.set_validity_period_end(validity_end.strftime("%Y-%m-%dT%H:%M+OOOO"))


parser = argparse.ArgumentParser()
parser.add_argument('--resolver', dest='resolver', required=True,
                    help="The resolver, in which the user should be created.")
parser.add_argument('--realm', dest='realm', required=True,
                    help="The realm of the user, to whom the token should be assigened.")
args = parser.parse_args()

i = 0
for line in sys.stdin:
    i += 1
    try:
        username, email, givenname, surname, hard_or_soft, attr1, attr2, pin, serial, validity = [x.strip() for x in line.split(",")]
        assign_user(args.resolver, args.realm, username, email, givenname, surname,
                    serial, pin, attr1, attr2, validity, hard_or_soft)
    except ValueError:
        sys.stderr.write("Malformed line {0!s}. Probably wrong number of columns.\n".format(i))



