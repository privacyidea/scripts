#!/opt/privacyidea/bin/python
from flask import Flask
from privacyidea.lib.error import TokenAdminError, UserError, ResourceNotFoundError
from privacyidea.lib.token import assign_token, unassign_token
from privacyidea.lib.user import User, create_user
import argparse
from flask_sqlalchemy import SQLAlchemy
from privacyidea.app import create_app
import sys

__doc__ = """
This script re-assigns tokens to users.
This comes in handy, if users have been changed in the resolver configuration.
The script takes a CSV file

   re-assign-token.py --realm <name> < tokens.csv

The CSV file should look like this:

serial, tokentype, username

It takes the output from 

    privacyidea-token-janitor find --csv --action listuser --assigned True --orphaned 0

Adapt it to your needs.

(c) 2023, Cornelius Kölbel <cornelius.koelbel@netknights.it>

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


parser = argparse.ArgumentParser()
parser.add_argument('--realm', dest='realm', required=True,
                    help="The realm of the user, to whom the token should be assigned.")
args = parser.parse_args()


app = create_app(config_name="production",
                 config_file="/etc/privacyidea/pi.cfg",
                 silent=True)
realm = args.realm

with app.app_context():
    i = 0
    for line in sys.stdin:
        i += 1
        try:
            vals = [x.strip().strip("'") for x in line.split(",")]
            serial = vals[0]
            username = vals[2]
            # User operations. First check the user, otherwise we will early fail
            print("+ Processing user {0!s}@{1!s}.".format(username, realm))
            user_obj = User(username, realm)
            # Token operation
            print(" +- Processing token {0!s}".format(serial))
            r = unassign_token(serial)
            t = assign_token(serial, user_obj)
            print(" +-- Assigned token to user {0!s}.".format(user_obj))
        except UserError as err:
            sys.stderr.write(" +-- Failed finding user: {0!s}.\n".format(err))
        except TokenAdminError as err:
            sys.stderr.write(" +-- Failed assigning token {0!s}: {1!s}.\n".format(serial, err))
        except ResourceNotFoundError as err:
            sys.stderr.write(" +-- Failed assigning token {0!s}: {1!s}.\n".format(serial, err))
        except ValueError:
            sys.stderr.write("Malformed line {0!s}. Probably wrong number of columns.\n".format(i))



