#!/opt/privacyidea/bin/

# debug enables logging of time delays to the privacyidea DEBUG log
VERBOSE = True

if VERBOSE:
    import timeit
    start = timeit.default_timer()

from privacyidea.lib.error import TokenAdminError
from privacyidea.lib.user import User, create_user
import argparse
from privacyidea.app import create_app
from privacyidea.lib.user import get_user_list
from privacyidea.lib.token import get_tokens
import sys
import os
from privacyidea.models import TokenOwner

__doc__ = """
This script copies the users from all userID resolvers in a source realm
to a single new resolver in a target realm and reassigns all existing tokens
to the according new users in the target realm.

The method create_new_user_attributes can be used to enrich the user
attributes in the new resolver.

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
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
"""


def create_new_user_attributes(base_user_attributes):
    """
    This method is used to modify and enrich the user attributes of the
    new users.
    """
    # copy user attributes dictionary
    ret_user_attributes = dict(base_user_attributes)
    # delete some table-specific attributes
    del ret_user_attributes['id']
    del ret_user_attributes['userid']
    # we may also add the original resolver as "group"
    # "group" must be mapped to a valid table column in the resolver config
    ret_user_attributes.update({"group": base_user_attributes["resolver"]})
    return ret_user_attributes


def merge_resolvers(source_realm, target_resolver, target_realm):
    # get a user list for source_realm
    user_list = get_user_list({"realm": source_realm})
    # iterate through the user list
    for source_user_attrs in user_list:
        # create new user attributes based on the original attributes
        new_user_attrs = create_new_user_attributes(source_user_attrs)
        # check for an existing user with the same name in the target
        # resolver if no user exists, create one in the new resolver
        # and reassign existing tokens
        if not get_user_list({"resolver": target_resolver,
                              "username": new_user_attrs["username"]}):
            try:
                create_user(target_resolver, new_user_attrs)
                sys.stdout.write("Created user {0!s} in resolver {1!s}."
                                 "\n".format(new_user_attrs["username"],
                                             target_resolver))
            except Exception as err:
                sys.stderr.write("Failed to create user: {0!s}."
                                 "\n".format(err))
                continue
            # create user objects to search and assign tokens
            source_user_obj = User(source_user_attrs["username"],
                                   source_realm,
                                   resolver=source_user_attrs["resolver"])
            new_user_obj = User(new_user_attrs["username"],
                                target_realm,
                                resolver=target_resolver)
            # get the tokens assigned to the treated user and reassign them
            # to the new user
            source_token_list = get_tokens(user=source_user_obj)
            for token_obj in source_token_list:
                try:
                    # use db level to change token owner (lib functions
                    # unassign_token and assign_token reset failcount and pin)
                    TokenOwner.query.filter(
                        TokenOwner.token_id == token_obj.token.id).delete()
                    token_obj.add_user(new_user_obj)
                    token_obj.save()
                    sys.stdout.write("Assigned token {0!s} to {1!s}@{2!s}."
                                     "\n".format(token_obj.token.serial,
                                                 new_user_attrs["username"],
                                                 target_realm))
                except TokenAdminError as err:
                    sys.stdout.write("Failed to unassign and assign token "
                                     "{0!s}: {1!s}.\n".format(token_obj.token.serial,
                                                              err))
                    continue
        else:
            sys.stderr.write("User with username {0!s} already exists in resolver "
                             "{1!s}.\n".format(new_user_attrs["username"],
                                               target_resolver))


# parse command line arguments
parser = argparse.ArgumentParser()
parser.add_argument('--source_realm', dest='source_realm', required=True,
                    help="Source realm where users and tokens are located.")
parser.add_argument('--target_resolver', dest='target_resolver', required=True,
                    help="Target resolver, where users are copied to. "
                         "Duplicates are skipped.")
parser.add_argument('--target_realm', dest='target_realm', required=True,
                    help="Assigned tokens of users in the source realm are "
                         "reassigned to the copied users in this realm.")
args = parser.parse_args()

# create app to talk to the privacyIDEA instance
app = create_app(config_name="production",
                 config_file="/etc/privacyidea/pi.cfg",
                 silent=True)

with app.app_context():
    merge_resolvers(args.source_realm, args.target_resolver,
                    args.target_realm)

if VERBOSE:
    stop = timeit.default_timer()
    sys.stderr.write("{0!s}: Script runtime: {1:.2f} s"
                     "\n".format(os.path.basename(__file__), stop - start))
