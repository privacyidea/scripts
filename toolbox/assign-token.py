#!/opt/privacyidea/bin/python
from flask import Flask
from privacyidea.lib.error import TokenAdminError, UserError, ResourceNotFoundError
from privacyidea.lib.token import assign_token
from privacyidea.lib.user import User, create_user
import argparse
from flask_sqlalchemy import SQLAlchemy
from privacyidea.app import create_app
import sys

__doc__ = """
This creates a user in the configured resolver and assigns an
existing token to this user and sets the token PIN.
If the user already exists, it simply assigns the token.

The script takes a CSV file

   assign-token.py --realm <name> < tokens.csv

The CSV file should look like this:

serial, username

Adapt it to your needs.

(c) 2022, Cornelius Kölbel <cornelius.koelbel@netknights.it>

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


def assign_user(realm, username, serial):
    app = create_app(config_name="production",
                     config_file="/etc/privacyidea/pi.cfg",
                     silent=True)

    with app.app_context():

        try:
            # User operations
            print("+ Processing user {0!s}@{1!s}.".format(username, realm))
            user_obj = User(username, realm)
            # Token operation
            print(" +- Processing token {0!s}".format(serial))
            t = assign_token(serial, user_obj)
            print(" +-- Assigned token to user {0!s}.".format(user_obj))
        except UserError as err:
            sys.stderr.write(" +-- Failed finding user: {0!s}.\n".format(err))
        except TokenAdminError as err:
            sys.stderr.write(" +-- Failed assigning token {0!s}: {1!s}.\n".format(serial, err))
        except ResourceNotFoundError as err:
            sys.stderr.write(" +-- Failed assigning token {0!s}: {1!s}.\n".format(serial, err))


parser = argparse.ArgumentParser()
parser.add_argument('--realm', dest='realm', required=True,
                    help="The realm of the user, to whom the token should be assigned.")
args = parser.parse_args()

i = 0
for line in sys.stdin:
    i += 1
    try:
        serial, username = [x.strip() for x in line.split(",")]
        assign_user(args.realm, username, serial)
    except ValueError:
        sys.stderr.write("Malformed line {0!s}. Probably wrong number of columns.\n".format(i))



