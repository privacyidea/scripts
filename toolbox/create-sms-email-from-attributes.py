#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  2024-09-02 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#             Init
#
from __future__ import print_function
__doc__ = """This script will read all users from a realm.

It then iterates the users and searches for user attributes for mobile number and email address.

If the attributes are set, it checks if the user has an sms token/email token with the given value.

If not, the corresponding token is created.

"""
from sqlalchemy.schema import Sequence
import sys
import argparse
import json
import getopt

import re
from privacyidea.lib.user import get_user_list, User
from privacyidea.lib.token import get_tokens, init_token
from privacyidea.app import create_app

# Please adapt these values accordingly

CONFIG = "/etc/privacyidea/pi.cfg"


def create_tokens(pi_app, realm, mobile_attr, email_attr):
    with (pi_app.app_context()):
        # find all the users
        userlist = get_user_list(param={"realm": realm})

        for user_dict in userlist:
            # Check, if user has the given attributes
            check_mail = email_attr and bool(user_dict.get(email_attr))
            check_mobile = mobile_attr and bool(user_dict.get(mobile_attr))
            if check_mobile or check_mail:
                user_obj = User(user_dict.get("username"), realm=realm)
                # Check if a token with the given value already exists
                tokens = get_tokens(user=user_obj)

                create_mobile = True
                create_mail = True
                for token in tokens:
                    print("User: {0!s}, checking token: {1!s}".format(user_obj, token.token.get("serial")))
                    if token.token.get("tokentype") == "sms" and check_mobile:
                        # compare the phone number
                        if token.get_tokeninfo("phone") == user_dict.get(mobile_attr):
                            create_mobile = False
                    if token.token.get("tokentype") == "email" and check_mail:
                        # compare the email address
                        if token.get_tokeninfo("email") == user_dict.get(email_attr):
                            create_mail = False

                # If not: Create the token
                if create_mobile and check_mobile:
                    init_token({"phone": user_dict.get(mobile_attr),
                                   "type": "sms",
                                   "genkey": 1}, user=user_obj)
                    print("Created SMS token for user: {0!s}".format(user_obj))
                if create_mail and check_mail:
                     init_token({"email": user_dict.get(email_attr),
                                   "type": "email",
                                   "genkey": 1}, user=user_obj)
                     print("Created Email token for user: {0!s}".format(user_obj))


def main():

    # parse input arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('--realm', dest='realm', required=True,
                        help="Realm of the users to create tokens in")
    parser.add_argument('--config', dest='config', required=False,
                        help="Location of config file (/etc/privacyidae/pi.cfg)")
    parser.add_argument('--mobileattr', dest='mobile_attr', required=False,
                        help="Create SMS tokens from this user attribute.")
    parser.add_argument('--emailattr', dest='email_attr', required=False,
                        help="Create Email tokens from this user attribute.")
    args = parser.parse_args()

    pi_app = create_app(config_name="production",
                        config_file=args.config or CONFIG,
                        silent=True)

    create_tokens(pi_app, args.realm, args.mobile_attr, args.email_attr)


if __name__ == '__main__':
    main()
