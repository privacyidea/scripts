#!/opt/privacyidea/bin/python

from privacyidea.lib.token import get_tokens, get_one_token, remove_token
from privacyidea.lib.user import User
import argparse
from privacyidea.app import create_app
import logging

__doc__ = """
This script removes tokens of a given user except the one given by serial.

This is a script that can be called by the privacyIDEA script handler. It
is designed to run as a post event handler at /token/init. It will remove
all tokens of the user but the token, which was just enrolled.

The script can be configured to remove only tokens which share the type
with the token that was just enrolled. It can act on all tokens or on the
active ones only. It can optionally restrict to those which have a
specific tokeninfo (e.g. software tokens).

It takes the arguments

   remove-other-user-tokens.py --user <user> --realm <realm> --serial <token serial>

You can place the script in your scripts directory /etc/privacyidea/scripts/
and use it in the script event handler. It logs with level info and debug to
the privacyidea log file.

Adapt REMOVE_OTHER_TOKENS_PER, ONLY_ACTIVE and TOKENINFO to your needs.

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

# "type": remove other tokens of the given user that share the type of the token given by serial.
# "user": remove all tokens of the given user except the one given by serial. This is the default.
REMOVE_OTHER_TOKENS_PER = "user"
# set to True to remove only active tokens
ONLY_ACTIVE = True
# remove only tokens which have the following tokeninfo
TOKENINFO = {"tokenkind": "software"}

log = logging.getLogger("privacyidea.scripts.remove-other-tokens")


def remove_other_tokens(serial, username, realm):
    user_obj = User(login=username, realm=realm)
    # get the token which was enrolled during the triggering /token/init
    token_obj = get_one_token(serial=serial, user=user_obj)
    if token_obj:
        tokentype = token_obj.type if REMOVE_OTHER_TOKENS_PER == "type" else None
        active = True if ONLY_ACTIVE is True else None
        # remove tokens if any
        for tok in get_tokens(user=user_obj, tokentype=tokentype, active=active,
                              tokeninfo=TOKENINFO or None):
            if tok.token.serial and tok.token.serial != serial:
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
parser.add_argument('--serial', required=True, dest='serial',
                    help="The serial of the enrolled token.")
parser.add_argument('--user', required=True, dest='username',
                    help="The username of the user of whom other tokens will be removed.")
parser.add_argument('--realm', required=True, dest='realm',
                    help="The realm of the user to act on.")
args = parser.parse_args()

app = create_app(config_name="production",
                 config_file="/etc/privacyidea/pi.cfg",
                 silent=True)

with app.app_context():
    log.info("Starting script to remove tokens different from {0!s} per {1!s} with tokeninfo {2}"
             "".format(args.serial, REMOVE_OTHER_TOKENS_PER, TOKENINFO))
    remove_other_tokens(args.serial, args.username, args.realm)
