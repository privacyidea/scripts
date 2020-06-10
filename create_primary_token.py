#!/usr/bin/env python

# debug enables logging of time delays to the privacyidea DEBUG log
DEBUG = True

if DEBUG:
    import timeit
    start = timeit.default_timer()

import argparse
import os
import logging

__doc__ = """
This scripts creates new tokens of the specified types for all users in a
given realm who do not already have an active token of this type.
This script can be run from the privacyIDEA event handler or as root,
e.g. from a cronjob to make sure every user has a base set of tokens.
The script is usually called with the argument --realm <REALM>. It can also
be used to enroll the primary tokens for a specific user with the additional
argument --user <USER>.
(c) 2020, Henning Hollermann <henning.hollermann@netknights.it>
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

ADMIN_USER = "tokenadmin"
PRIMARY_TOKEN_TYPES = ["email"]

log = logging.getLogger("privacyidea.create_primary_token.py")

def create_primary_tokens(realm, username=None):
    app = create_app(config_name="production",
                     config_file="/etc/privacyidea/pi.cfg",
                     silent=True)

    with app.app_context():
        # if no username is given, get all users from the specified realm
        if not username or username == 'none':
            user_list = get_user_list({"realm": realm})
            user_objects = [User(user["username"], realm)
                            for user in user_list]
        # else, get only the specified user
        else:
            user_objects = [User(username, realm)]
        for user_obj in user_objects:
            for type in PRIMARY_TOKEN_TYPES:
                tokens = get_tokens(user=user_obj, tokentype=type,
                                    active=True)
                # if no token of the specified type exists, create one
                if len(tokens) == 0:
                    params = {"type": type, "dynamic_email": True}
                    init_token(params, user_obj)
                    log.info('Enrolled a primary {0!s} token '
                             'for {1!s}@{2!s}'.format(type, username, realm))


# parse input arguments
parser = argparse.ArgumentParser()
parser.add_argument('--user', dest='username',
                    help="Create primary tokens only for this "
                    "specific user in the given realm")
parser.add_argument('--realm', dest='realm', required=True,
                    help="Realm for which the primary tokens "
                    "should be created (required argument)")
parser.add_argument('--logged_in_user', dest='logged_in_user',
                    help="Triggering user")
parser.add_argument('--logged_in_role', dest='logged_in_role',
                    help="Role of the triggering user (user or admin)")
parser.add_argument('--serial', dest='serial',
                    help="Token serial (unsupported)")
args = parser.parse_args()

# check for privileges to run the script and only proceed then
if os.geteuid() == 0 or \
        (args.logged_in_role == "admin" and ADMIN_USER in args.logged_in_user):

    # catch event handler called from WebUI without realm context
    if args.realm != 'none':

        # for reasons of speed in the unprivileged case, imports are placed here
        from privacyidea.lib.token import init_token, get_tokens
        from privacyidea.lib.user import User, get_user_list
        from privacyidea.app import create_app

        # start the action
        ret = create_primary_tokens(args.realm, username=args.username)

if DEBUG:
    stop = timeit.default_timer()
    log.debug("auto-enrollment script runtime: {0:.2f} s".format(stop - start))
