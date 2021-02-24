#!/opt/privacyidea/bin/python

from privacyidea.lib.token import get_tokens, remove_token
from privacyidea.lib.user import User
import argparse
from privacyidea.app import create_app
import logging

__doc__ = """
This script removes tokens of the specified type for a given user.

This is a script that can be called by the privacyIDEA script handler. It
is designed to run as a pre event handler at /token/init. It will remove all
tokens of the user of a specific type and thus ensure that the user has always
only one token.

Restrict the event handler well to the users or realms where this should happen.

The script can be configured to remove only active tokens and optionally restrict
to those which have a specific tokeninfo (e.g. software tokens).

It takes the arguments

   remove-user-tokens.py --user <user> --realm <realm>

You can place the script in your scripts directory /etc/privacyidea/scripts/
and use it in the script event handler. It logs with level info and debug to
the privacyidea log file.

Adapt REMOVE_TYPE, ONLY_ACTIVE and TOKENINFO to your needs.

(c) 2021, Henning Hollermann <henning.hollermann@netknights.it>

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

# REMOVE_TYPE can be a specific tokentype like "totp" or "all" to remove all
# tokens of the user
REMOVE_TYPE = "totp"
# set to True to remove only active tokens
ONLY_ACTIVE = True
# remove only tokens which have the following tokeninfo
TOKENINFO = {"tokenkind": "software"}

log = logging.getLogger("privacyidea.scripts.remove-other-tokens")


def remove_user_tokens(username, realm):
    user_obj = User(login=username, realm=realm)
    # get the token which was enrolled during the triggering /token/init
    active = True if ONLY_ACTIVE is True else None
    tokentype = None if REMOVE_TYPE == "all" else REMOVE_TYPE.lower()
    # remove tokens if any
    for tok in get_tokens(user=user_obj, tokentype=tokentype, active=active,
                          tokeninfo=TOKENINFO or None):
        if tok.token.serial:
            remove_token(serial=tok.token.serial)
            log.debug("- Remove token with serial {0!s}".format(tok.token.serial))
    # check remaining tokens
    remaining_tokens = get_tokens(user=user_obj)
    log.debug("User {0!s}@{1!s} has {2!s} remaining tokens."
              "".format(username, realm, len(remaining_tokens)))
    for tok in remaining_tokens:
        log.debug("~ a {0!s} token with serial {1!s}".format(tok.type.upper(),
                                                             tok.token.serial))

parser = argparse.ArgumentParser()
parser.add_argument('--user', required=True, dest='username',
                    help="The username of the user of whom the tokens will be removed.")
parser.add_argument('--realm', required=True, dest='realm',
                    help="The realm of the user to act on.")
args = parser.parse_args()

app = create_app(config_name="production",
                 config_file="/etc/privacyidea/pi.cfg",
                 silent=True)

with app.app_context():
    log.info("Starting script to remove tokens of type {0!s} with tokeninfo {1}"
             "".format(REMOVE_TYPE, TOKENINFO))
    remove_user_tokens(args.username, args.realm)
