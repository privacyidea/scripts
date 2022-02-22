#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  2022-02-16 Cornelius Kölbel <cornelius.koelbel@netknights.it>
#             Init
#
from __future__ import print_function
__doc__ = """You can use this script to migrate tokens from one privacyIDEA instance to another privacyIDEA instance.
The token data is copied on a database level thus preserving the hashed PIN and the token seeds.
Note: The same encryption keys need to be used.

You need to provide the two pi.cfg files of the two instances. 
Note: Using the same pi.cfg file, you could copy tokens within one instance.

In the sections MIGRATE->user you can specify, which users you want to find, so that the
script does not need to iterate through all users.
The pattern defines a search pattern on the username, that needs to match.
Rules for regular expression apply.
You can then define the new username in "replace".
The "attributes" define, which user attributes should be copied. Then the user is created on the new instance.

All tokens of this found user are migrated. However, you can use the section MIGRATE->serial to change the
serial number of the migrated tokens.

The section ASSIGNMENTS defines, in which resolver and realm the new user shall be created.

"""
from sqlalchemy.schema import Sequence
import sys
import json
import getopt

import re
from privacyidea.models import TokenInfo, MethodsMixin
from privacyidea.app import create_app
from privacyidea.lib.user import get_user_list, create_user, User
from privacyidea.lib.token import get_tokens, assign_token
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

EXAMPLE_CONFIG_FILE = """{
    "SQL": {
        "PRIVACYIDEA_FROM": "/etc/privacyidea/pi.cfg",
        "PRIVACYIDEA_TO": "/etc/newprivacyidea/pi.cfg"
    },
    "MIGRATE": {
        "user": { "find": {"username": "*@example.com", "realm": "RealmA" },
                  "pattern": "^(.*?)@example.com$",
                  "replace": "\\1",
                  "attributes": ['email', 'givenname', 'surname']},
        "serial": { "pattern": "^(.*)$",
                    "replace": "\\_new" }
    },
    "ASSIGNMENTS": {
        "to_realm": "realmC",
        "to_resolver": "resolverC"
    }
}"""


class Token(MethodsMixin, db.Model):
    """
    The "Token" table contains the basic token data.

    It contains data like
     * serial number
     * secret key
     * PINs
     * ...

    The table :py:class:`privacyidea.models.TokenOwner` contains the owner
    information of the specified token.
    The table :py:class:`privacyidea.models.TokenInfo` contains additional information
    that is specific to the tokentype.
    """
    __tablename__ = 'token'
    __table_args__ = {'mysql_row_format': 'DYNAMIC'}
    id = db.Column(db.Integer, Sequence("token_seq"),
                   primary_key=True,
                   nullable=False)
    description = db.Column(db.Unicode(80), default=u'')
    serial = db.Column(db.Unicode(40), default=u'',
                       unique=True,
                       nullable=False,
                       index=True)
    tokentype = db.Column(db.Unicode(30),
                          default=u'HOTP',
                          index=True)
    user_pin = db.Column(db.Unicode(512),
                         default=u'')  # encrypt
    user_pin_iv = db.Column(db.Unicode(32),
                            default=u'')  # encrypt
    so_pin = db.Column(db.Unicode(512),
                       default=u'')  # encrypt
    so_pin_iv = db.Column(db.Unicode(32),
                          default=u'')  # encrypt
    pin_seed = db.Column(db.Unicode(32),
                         default=u'')
    otplen = db.Column(db.Integer(),
                       default=6)
    pin_hash = db.Column(db.Unicode(512),
                         default=u'')  # hashed
    key_enc = db.Column(db.Unicode(1024),
                        default=u'')  # encrypt
    key_iv = db.Column(db.Unicode(32),
                       default=u'')
    maxfail = db.Column(db.Integer(),
                        default=10)
    active = db.Column(db.Boolean(),
                       nullable=False,
                       default=True)
    revoked = db.Column(db.Boolean(),
                        default=False)
    locked = db.Column(db.Boolean(),
                       default=False)
    failcount = db.Column(db.Integer(),
                          default=0)
    count = db.Column(db.Integer(),
                      default=0)
    count_window = db.Column(db.Integer(),
                             default=10)
    sync_window = db.Column(db.Integer(),
                            default=1000)
    rollout_state = db.Column(db.Unicode(10),
                              default=u'')

    def __init__(self, serial, tokentype=u"", otplen=6,
                 key_enc=None, key_iv=None, description=None,
                 pin_seed=None, count=0, failcount=0, maxfail=10,
                 active=True, locked=False, revoked=False,
                 count_window=10, pin_hash=None, sync_window=1000,
                 rollout_state="",
                 **kwargs):
        super(Token, self).__init__(**kwargs)
        self.serial = u'' + serial
        self.tokentype = tokentype
        self.count = count
        self.failcount = failcount
        self.maxfail = maxfail
        self.active = active
        self.revoked = revoked
        self.locked = locked
        self.count_window = count_window
        self.otplen = otplen
        self.pin_seed = pin_seed
        self.key_enc = key_enc
        self.key_iv = key_iv
        self.description = description
        self.pin_hash = pin_hash,
        self.sync_window = sync_window
        self.rollout_state = rollout_state


class Config(object):

    def __init__(self, config_file):
        with open(config_file, "r") as f:
            contents = f.read()
        config = json.loads(contents)
        self.ASSIGNMENTS = config.get("ASSIGNMENTS")
        self.PRIVACYIDEA_FROM = config.get("SQL").get("PRIVACYIDEA_FROM")
        self.PRIVACYIDEA_TO = config.get("SQL").get("PRIVACYIDEA_TO")
        self.INSERT_CHUNK_SIZE = config.get("SQL").get("INSERT_CHUNK_SIZE")
        self.MIGRATE = config.get("MIGRATE")
        self.MIGRATE_USER = self.MIGRATE.get("user")
        self.MIGRATE_USER_FIND = self.MIGRATE_USER.get("find")
        self.MIGRATE_USER_PATTERN = self.MIGRATE_USER.get("pattern")
        self.MIGRATE_USER_REPLACE = self.MIGRATE_USER.get("replace")
        self.TO_RESOLVER = self.ASSIGNMENTS.get("to_resolver")
        self.TO_REALM = self.ASSIGNMENTS.get("to_realm")
        self.MIGRATE_ATTRIBUTES = self.MIGRATE.get("user").get("attributes", [])
        self.MIGRATE_SERIAL_PATTERN = self.MIGRATE.get("serial", {}).get("pattern")
        self.MIGRATE_SERIAL_REPLACE = self.MIGRATE.get("serial", {}).get("replace")


def dict_without_keys(d, keys):
    new_d = d.copy()
    for key in keys:
        if key in d:
            new_d.pop(key)
    return new_d


def token_to_dict(token):
    """
    Store the database columns of the token into a dict.
    Also store the tokeninfo into a list of dicts.

    :param token: The database token object
    :return: a dict, containing the token and the tokeninfo
    """
    token_dict = {}
    columns = token.__table__.c
    for column in columns:
        value = getattr(token, column.key)
        if column.key not in ('id'):
            token_dict[column.key] = value
    # Now add the tokeninfo
    info_list = []
    for ti in token.info_list:
        tokeninfo = {"Description": ti.Description,
                     "Key": ti.Key,
                     "Type": ti.Type,
                     "Value": ti.Value}
        info_list.append(tokeninfo)
    token_dict["info_list"] = info_list
    return token_dict


def create_token_from_dict(serialized_token, info_list):
    """
    
    :param serialized_token: dict containing all token objects 
    :return: database ID of the token
    """
    # create database object directly, since we have the encrypted data
    r = Token(**serialized_token).save()
    for ti in info_list:
        ti["token_id"] = r
        TokenInfo(**ti).save()
    return r


def migrate(config_obj):

    from_app = create_app(config_name="production",
                          config_file=config_obj.PRIVACYIDEA_FROM,
                          silent=True)

    to_app = create_app(config_name="production",
                        config_file=config_obj.PRIVACYIDEA_TO,
                        silent=True)

    new_users = []
    new_tokens = []

    with from_app.app_context():
        # find all the users
        userlist = get_user_list(param=config_obj.MIGRATE_USER_FIND)
        for user in userlist:
            if re.match(config_obj.MIGRATE_USER_PATTERN, user.get("username")):
                new_username = re.sub(config_obj.MIGRATE_USER_PATTERN, config_obj.MIGRATE_USER_REPLACE, user.get("username"))
                new_user = {"username": new_username,
                            "tokenlist": []}
                for attr in config_obj.MIGRATE_ATTRIBUTES:
                    new_user[attr] = user.get(attr)

                tokens = get_tokens(user=User(user.get("username"), realm=config_obj.MIGRATE_USER_FIND.get("realm")))
                for token in tokens:
                    new_tokens.append(token_to_dict(token.token))
                    new_user["tokenlist"].append(token.token.serial)
                new_users.append(new_user)

    with to_app.app_context():
        # create the new tokens
        for tok in new_tokens:
            if config_obj.MIGRATE_SERIAL_PATTERN:
                tok["serial"] = re.sub(config_obj.MIGRATE_SERIAL_PATTERN,
                                       config_obj.MIGRATE_SERIAL_REPLACE,
                                       tok["serial"])
            info_list = tok.get("info_list")
            del (tok["info_list"])
            toks = get_tokens(serial=tok.get("serial"))
            if len(toks) > 0:
                print("New token {0!s} aleady exists.".format(tok.get("serial")))
            else:
                create_token_from_dict(tok, info_list)

        # create the new users
        for user in new_users:
            tokenlist = user.get("tokenlist")
            del(user["tokenlist"])

            ul = get_user_list({"username": user.get("username"),
                                "realm": config_obj.TO_REALM,
                                "resolver": config_obj.TO_RESOLVER})
            if not ul:
                uid = create_user(config_obj.TO_RESOLVER, user)
                print("Created user {0!s}".format(uid))
            else:
                print("User already exists!")
            user_obj = User(login=user.get("username"),
                            realm=config_obj.TO_REALM,
                            resolver=config_obj.TO_RESOLVER)

            # Assign token
            for serial in tokenlist:
                serial = re.sub(config_obj.MIGRATE_SERIAL_PATTERN,
                               config_obj.MIGRATE_SERIAL_REPLACE,
                               serial)
                print("Assigning token {0!s} to user {1!s}".format(serial, user_obj))
                try:
                    assign_token(serial, user_obj)
                except Exception:
                    print("Error assigning token - probably the token is already assigned.")


def usage():
    print("""
migrate-token.py --generate-example-config [--config <config file>]

    --generate-example-config, -g   Output an example config file. 
                                    This is a JSON file, that needs to be passed
                                    to this command.

    --config, -c <file>             The config file, that contains the complete
                                    configuration.

{0!s}
""".format(__doc__))


def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hgc:", ["help", "generate-example-config", "config="])
    except getopt.GetoptError as e:
        print(str(e))
        sys.exit(1)

    config_file = None
    generate_config = False

    for o, a in opts:
        if o in ("-g", "--generate-example-config"):
            generate_config = True
            print(EXAMPLE_CONFIG_FILE)
        elif o in ("-c", "--config"):
            config_file = a
        elif o in ("-h", "--help"):
            usage()
            sys.exit(2)

    if config_file:
        config_obj = Config(config_file)
        migrate(config_obj)
        sys.exit(0)

    else:
        if not generate_config:
            usage()
            sys.exit(1)


if __name__ == '__main__':
    main()
