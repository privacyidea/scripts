#!/opt/privacyidea/bin/python
from flask import Flask
from privacyidea.lib.token import init_token
from privacyidea.lib.tokenclass import TOKENKIND
import argparse
from flask_sqlalchemy import SQLAlchemy
from privacyidea.app import create_app
import sys

__doc__ = """
This imports a CSV file of tokens.     

   import-token.py --tokenrealm <name> < tokens.csv

The CSV file should look like this:

    serial, seed, counter

The tokens are always HOTP tokens.
The hash algorithm is determined by the length of the seed.
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


def import_token(tokenrealm, serial, seed, counter):
    app = create_app(config_name="production",
                     config_file="/etc/privacyidea/pi.cfg",
                     silent=True)

    with app.app_context():
        try:
            print(" +- Processing token {0!s}".format(serial))

            if len(seed) == 40:
                hash = "sha1"
            elif len(seed) == 64:
                hash = "sha256"
            else:
                raise Exception("Long seed length.")
            init_param = {'serial': serial,
                          'otpkey': seed,
                          'hashlib': hash,
                          'description': "imported"}
            # Imported tokens are usually hardware tokens
            token = init_token(init_param,
                               tokenrealms=[tokenrealm],
                               tokenkind=TOKENKIND.HARDWARE)
            token.set_otp_count(counter)
        except Exception as err:
            sys.stderr.write(" +-- Failed importing token {0!s}: {1!s}.\n".format(serial, err))


parser = argparse.ArgumentParser()
parser.add_argument('--tokenrealm', dest='tokenrealm', required=False,
                    help="The realm into which the tokens should be assigned.")
args = parser.parse_args()

i = 0
for line in sys.stdin:
    i += 1
    try:
        serial, seed, counter = [x.strip() for x in line.split(",")]
        import_token(args.tokenrealm, serial, seed, counter)
    except ValueError:
        sys.stderr.write("Malformed line {0!s}. Probably wrong number of columns.\n".format(i))



