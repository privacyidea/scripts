#!/opt/privacyidea/bin/python
from flask import Flask
from privacyidea.lib.error import TokenAdminError, UserError, ResourceNotFoundError
from privacyidea.lib.token import assign_token, unassign_token, get_tokens
from privacyidea.lib.user import User, create_user
import argparse
from flask_sqlalchemy import SQLAlchemy
from privacyidea.app import create_app
import sys

__doc__ = """
This script re-assigns tokens to users from one realm to another realm and resolver
The login name of the user stays the same.

   reassign-tokens.py --from_realm --from_resolver --to_realm --to_resolver

Adapt it to your needs.

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

parser = argparse.ArgumentParser()
parser.add_argument('--to_realm', dest='to_realm', required=True,
                    help="The new realm of the tokenowner.")
parser.add_argument('--to_resolver', dest='to_resolver', required=True,
                    help="The new resolver of the tokenowner.")
parser.add_argument('--from_realm', dest='from_realm', required=True,
                    help="The old realm of the tokenowner.")
parser.add_argument('--from_resolver', dest='from_resolver', required=True,
                    help="The old resolver of the tokenowner.")
parser.add_argument('--dry_run', dest='dry_run', action='store_true')
args = parser.parse_args()

to_realm = args.to_realm
to_resolver = args.to_resolver
from_realm = args.from_realm
from_resolver = args.from_resolver
dry_run = args.dry_run

app = create_app(config_name="production",
                 config_file="/etc/privacyidea/pi.cfg",
                 silent=True)

with app.app_context():
    toks = get_tokens(realm=from_realm, resolver=from_resolver)
    for tok in toks:
        serial = tok.token.serial
        print("Token {0!s} assigned to {1!s}@{2!s} will be migrated to resolver {3!s} in realm {4!s}.".format(
            serial, tok.user.login, from_realm, to_resolver, to_realm
        ))
        try:
            if tok.user:
                user_obj = User(tok.user.login, to_realm, resolver=to_resolver)
                if not dry_run:
                    unassign_token(serial)
                    assign_token(serial, user_obj)

                print(" +-- Assigned token {0!s} to user {1!s}.".format(serial, user_obj))
        except UserError as err:
            sys.stderr.write(" +-- Failed finding user: {0!s}.\n".format(err))
        except TokenAdminError as err:
            sys.stderr.write(" +-- Failed assigning token {0!s}: {1!s}.\n".format(serial, err))
        except ResourceNotFoundError as err:
            sys.stderr.write(" +-- Failed assigning token {0!s}: {1!s}.\n".format(serial, err))
