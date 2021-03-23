#!/opt/privacyidea/bin/python

# debug enables logging of time delays to the privacyidea DEBUG log
DEBUG = True

if DEBUG:
    import timeit
    start = timeit.default_timer()

import argparse
import os
import logging
import urllib3
import requests

__doc__ = """
This scripts creates new tokens of the specified types for all users in a
given realm who do not already have a token of this type.
This script is run as root from the command line, e.g. from a cronjob to make
sure every user has a base set of tokens.
The script is usually called with the argument --realm <REALM>. It can also
be used to enroll the primary tokens for a specific user with the additional
argument --user <USER>.
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

URL = 'http://localhost:5000/'
VERIFY = False
ADMIN_USER = "admin"
ADMIN_PASSWORD = "test"
PRIMARY_TOKEN_TYPES = ["email"]
ADD_PARAMS = {"sms": {"dynamic_phone": True},
              "email": {"dynamic_email": True}}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("privacyidea.scripts.create_primary_token")


def get_auth_tok():
    r = requests.post(URL + '/auth', verify=VERIFY,
                      data={"username": ADMIN_USER, "password": ADMIN_PASSWORD})
    authorization = r.json().get("result").get("value").get("token")
    log.info('Auth token obtained')
    return authorization


def create_default_tokens_api(auth_token, realm, username=None):
    # for reasons of speed in the unprivileged case, imports are placed here
    from privacyidea.lib.token import init_token, get_tokens
    from privacyidea.lib.user import User, get_user_list
    from privacyidea.app import create_app

    app = create_app(config_name="production",
                     config_file="/etc/privacyidea/pi.cfg",
                     silent=True)

    with app.app_context():
        # if no username is given, get all users from the specified realm
        if not username:
            user_list = get_user_list({"realm": realm})
            user_objects = [User(user["username"], realm)
                            for user in user_list]
        # else, get only the specified user
        else:
            user_objects = [User(username, realm)]
        for user_obj in user_objects:
            if user_obj.exist():
                for type in PRIMARY_TOKEN_TYPES:
                    tokens = get_tokens(user=user_obj, tokentype=type)
                    # if no token of the specified type exists, create one
                    # create sms token only if mobile number exists
                    if len(tokens) == 0:
                        if (type == "email" and not user_obj.info.get("email")) or \
                           (type == "sms" and not user_obj.get_user_phone(index=0, phone_type='mobile')):
                            log.info("User {0!s} in realm {1!s} has no {2!s}. "
                                     "Not creating {2!s} token.".format(user_obj.login, user_obj.realm, type))
                            continue
                        else:
                            params = {"type": type}
                            params.update(ADD_PARAMS[type])
                            params.update({"user": user_obj.login, "realm": user_obj.realm})
                            r = requests.post(URL + '/token/init', verify=VERIFY,
                                              data=params,
                                              headers={"Authorization": auth_token})
                            serial = r.json().get("detail").get("serial")
                            if serial:
                                log.info('Enrolled a primary {0!s} token for '
                                         '{1!s}@{2!s}'.format(type, user_obj.login,
                                                              user_obj.realm))
                    else:
                        log.info("User {0!s} in realm {1!s} already has a {2!s} token. "
                                 "Not creating another one.".format(user_obj.login, user_obj.realm, type))
            else:
                log.info('User {0!s} does not exists in any resolver in '
                         'realm {1!s}'.format(user_obj.login, user_obj.realm))


# parse input arguments
parser = argparse.ArgumentParser()
parser.add_argument('--user', dest='username',
                    help="Create primary tokens only for this "
                         "specific user in the given realm")
parser.add_argument('--realm', dest='realm', required=True,
                    help="Realm for which the primary tokens "
                         "should be created (required argument)")
args = parser.parse_args()

# check for privileges to run the script and only proceed then
if os.geteuid() == 0:

    # get auth token
    auth_tok = get_auth_tok()
    # create tokens for users
    create_default_tokens_api(auth_tok, args.realm, username=args.username)
else:
    print("You are not root! Exiting.")

if DEBUG:
    stop = timeit.default_timer()
    log.info("auto-enrollment script runtime: {0:.2f} s".format(stop - start))
