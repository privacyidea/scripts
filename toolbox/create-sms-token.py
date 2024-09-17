#!/opt/privacyidea/bin/python
import sys
import argparse
import json
import getopt

import re
from privacyidea.lib.user import get_user_list, User
from privacyidea.lib.token import get_tokens, init_token
from privacyidea.app import create_app

__doc__ = """
This scripts creates an SMS token for the given user with the phone number.
If the user already has such token, it will not be created.
 
The script takes a CSV file

   create-sms-token.py  --realm <name>  < tokens.csv

The CSV file should look like this:

username, phone, ....

Adapt it to your needs.

(c) 2024, Cornelius Kölbel <cornelius.koelbel@netknights.it>

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

CONFIG = "/etc/privacyidea/pi.cfg"


def create_token(pi_app, realm, username, phone):
    with (pi_app.app_context()):
        print("Processing user: {0!s}@{2!s} with phone {1!s}.".format(username, phone, realm))
        user_obj = User(username, realm=realm)
        # Check if a token with the given value already exists
        tokens = get_tokens(user=user_obj)
        create_mobile = True
        for token in tokens:
            print("User: {0!s}, checking token: {1!s}".format(user_obj, token.token.get("serial")))
            if token.token.get("tokentype") == "sms":
                # compare the phone number
                if token.get_tokeninfo("phone") == phone:
                    create_mobile = False

        # If not: Create the token
        if create_mobile:
            init_token({"phone": phone,
                        "type": "sms",
                        "genkey": 1}, user=user_obj)
            print("Created SMS token for user: {0!s}".format(user_obj))


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('--config', dest='config', required=False,
                        help="Location of config file (/etc/privacyidae/pi.cfg)")
    parser.add_argument('--realm', dest='realm', required=True,
                        help="The realm of the user, to whom the token should be assigened.")
    args = parser.parse_args()

    pi_app = create_app(config_name="production",
                        config_file=args.config or CONFIG,
                        silent=True)

    i = 0
    for line in sys.stdin:
        i += 1
        try:
            values = [x.strip() for x in line.split(",")]
            username = values[0].strip()
            phone = values[1].strip()
            create_token(pi_app, args.realm, username, phone)
        except ValueError:
            sys.stderr.write("Malformed line {0!s}. Probably wrong number of columns.\n".format(i))
        except Exception as e:
            sys.stderr.write("Error processing line {0!s}: {1!s}\n".format(i, e))



if __name__ == '__main__':
    main()

