#!/opt/privacyidea/bin/python

# debug enables logging of script runtimes to the privacyidea DEBUG log
TRACK_TIME = True

if TRACK_TIME:
    import timeit
    start = timeit.default_timer()

import argparse
import sys
import logging
import urllib3
import requests

__doc__ = """
This scripts creates new tokens of the specified types for all users in a
given realm who do not already have a token of this type.

The script must be called with the argument --realm <REALM>. 
It can also be used to enroll the primary tokens for a specific user with 
the additional argument --user <USER>.

With the option --tokentype <TYPE> the hard-coded PRIMARY_TOKEN_TYPES can 
be overwridden.  You can add a userinfo condition to enroll primary tokens 
only for users which have the userinfo specified by --userinfo-key <KEY> 
and --userinfo-value <VAL>.

The tokens are either enrolled via Lib function (faster) or use the REST API
to enroll the token which also triggers event handlers configured in privacyIDEA. 
Set this via the variable INIT_VIA_API.
Note that the script must access also the library functions of privacyIDEA, so in
most cases it must be run on the privacyIDEA server.

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

# the URL of the privacyIDEA server (defaults to https://localhost/)
# URL = 'https://localhost:5000/'
# verify the SSL certificate of the privacyIDEA server (defaults to False)
# VERIFY = True
# use Lib or API layer to init token (triggers event handler)
INIT_VIA_API = True
ADMIN_USER = "admin"
ADMIN_PASSWORD = "test"
# the list of token types to enroll. Overwritten by --tokentype option.
PRIMARY_TOKEN_TYPES = ["registration"]
# dictionary with parameters to add for the respective tokentype
ADD_PARAMS = {"sms": {"dynamic_phone": True},
              "email": {"dynamic_email": True},
              "registration": {"description": "initial token"}}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger("privacyidea.scripts.create_primary_token")


def get_auth_tok():
    r = requests.post(URL + '/auth', verify=VERIFY,
                      data={"username": ADMIN_USER, "password": ADMIN_PASSWORD})
    if r.status_code == 200:
        authorization = r.json().get("result").get("value").get("token")
        log.info('Auth token obtained')
        return authorization
    else:
        error_msg = r.json().get("result").get("error").get("message")
        error_code = r.json().get("result").get("error").get("code")
        print("Error {0!s}: {1!s}".format(error_code, error_msg))
        sys.exit()


def check_userinfo(user_obj, userinfo_key=None, userinfo_value=None):
    """
    This method checks if the user has the given userinfo value
    """

    # if no condition is specified, skip the check
    if not userinfo_key and not userinfo_value:
        return True

    if userinfo_key in user_obj.info:
        if isinstance(user_obj.info[userinfo_key], str) and user_obj.info[userinfo_key] == userinfo_value or \
                isinstance(user_obj.info[userinfo_key], list) and userinfo_value in user_obj.info[userinfo_key]:
            return True
    else:
        log.debug("Userinfo key does not exists or value does not match"
                 " for user {0!s} in realm {1!s}.".format(user_obj.login,
                                                          user_obj.realm))
        return False


def create_default_tokens(realm, auth_token=None, username=None,
                          userinfo_key=None, userinfo_value=None,
                          tokentype=None):
    """
    This method creates the default tokens for the users in the given realm.
    You may add a userinfo condition.
    """
    # for reasons of speed in the unprivileged case, imports are placed here
    from privacyidea.lib.token import init_token, get_tokens
    from privacyidea.lib.user import User, get_user_list
    from privacyidea.app import create_app

    tokentypes = [tokentype] if tokentype else PRIMARY_TOKEN_TYPES

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
                if check_userinfo(user_obj, userinfo_key, userinfo_value):
                    for type in tokentypes:
                        serial = None
                        tokens = get_tokens(user=user_obj, tokentype=type)
                        # if no token of the specified type exists, create one
                        # create sms token only if mobile number exists
                        if len(tokens) == 0:
                            if (type == "email" and not user_obj.info.get("email")) or \
                               (type == "sms" and not user_obj.get_user_phone(index=0,
                                                                              phone_type='mobile')):
                                log.info("User attribute missing for user {0!s}@{1!s}."
                                         "Cannot create {2!s} token.".format(user_obj.login,
                                                                             user_obj.realm, type))
                                continue
                            else:
                                params = {"type": type}
                                params.update(ADD_PARAMS[type])
                                params.update({"user": user_obj.login, "realm": user_obj.realm})
                                if INIT_VIA_API:
                                    # enroll token via API (triggers event handlers at token_init)
                                    r = requests.post(URL + '/token/init', verify=VERIFY,
                                                      data=params,
                                                      headers={"Authorization": auth_token})
                                    status = r.json().get("result").get("status")
                                    if status is True:
                                        serial = r.json().get("detail").get("serial")
                                    else:
                                        error = r.json().get("result").get("error")
                                        log.info("Enrolling {0!s} token for user {1!s} in realm "
                                                 "{2!s} via API: {3!s}".format(type,
                                                                               user_obj.login,
                                                                               user_obj.realm,
                                                                               error.get("message")))
                                else:
                                    # enroll token via lib method (faster)
                                    token_obj = init_token(params, user_obj)
                                    serial = token_obj.token.serial
                                if serial:
                                    log.info('Enrolled a primary {0!s} token for '
                                             'user {1!s} in realm {2!s}'.format(type,
                                                                                user_obj.login,
                                                                                user_obj.realm))
                        else:
                            log.info("User {0!s} in realm {1!s} already has a {2!s} token. "
                                     "Not creating another one.".format(user_obj.login,
                                                                        user_obj.realm, type))
            else:
                log.info('User {0!s} does not exists in any resolver in '
                         'realm {1!s}'.format(user_obj.login, user_obj.realm))


# parse input arguments
parser = argparse.ArgumentParser()
parser.add_argument('--user', dest='username', required=False,
                    help="Create primary tokens only for this "
                         "specific user in the given realm")
parser.add_argument('--realm', dest='realm', required=True,
                    help="Realm for which the primary tokens "
                         "should be created (required argument)")
parser.add_argument('--userinfo-key', dest='userinfo_key', required=False,
                    help="Optional userinfo key")
parser.add_argument('--userinfo-value', dest='userinfo_value', required=False,
                    help="Create only tokens for users which have "
                         "this userinfo value.")
parser.add_argument('--tokentype', dest='tokentype', required=False,
                    help="Create tokens of this type. The default type "
                         "is set in the script by the variable PRIMARY_TOKEN_TYPES")
args = parser.parse_args()

# early exit for usage at endpoints without realm or user context
# nothing will be logged apart from the audit entry
if args.realm == 'none' or args.username == 'none':
    sys.exit()

# get auth token
if INIT_VIA_API:
    URL = URL if 'URL' in locals() else "https://localhost/"
    VERIFY = VERIFY if 'VERIFY' in locals() else False
    auth_tok = get_auth_tok()
else:
    auth_tok = None

# create tokens for users
create_default_tokens(args.realm,
                      auth_token=auth_tok, username=args.username,
                      userinfo_key=args.userinfo_key,
                      userinfo_value=args.userinfo_value,
                      tokentype=args.tokentype)


if TRACK_TIME:
    stop = timeit.default_timer()
    log.debug("auto-enrollment script runtime: {0:.2f} s".format(stop - start))
