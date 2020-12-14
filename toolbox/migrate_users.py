#!/usr/bin/env python
# -*- coding: utf-8 -*-

__doc__ = """
This script can assign token to users from a new resolver i.e. when the users
were migrated to a new resolver and the UID Type has changed.

(c) 2020, Paul Lettich <paul.lettich@netknights.it>
 
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

PI_CONFIG = '/etc/privacyidea/pi.cfg'
FROM_RESOLVER = 'netknights-lab'
TO_RESOLVER = 'ldapresolver2'
MIGRATE_REALM = 'migrate'


def main():
    from privacyidea.app import create_app
    from privacyidea.lib.token import get_tokens, unassign_token, assign_token
    from privacyidea.lib.user import User

    app = create_app(config_name="production",
                     config_file=PI_CONFIG,
                     silent=True)
    with app.app_context():
        tokens = get_tokens(resolver=FROM_RESOLVER)
        for token in tokens:
            user = token.user
            # find user in other resolver
            if user.exist():
                other_user = User(user.login, resolver=TO_RESOLVER, realm=MIGRATE_REALM)
                if other_user.exist():
                    print('{0!s}: {1!s} -> {2!s}'.format(token.get_serial(),
                                                         user, other_user))
                    unassign_token(token.get_serial())
                    token.add_user(other_user)
                else:
                    print('{0!s}: {1!s} -> Could not find user with login {2!s} '
                          'in resolver {3!s}'.format(token.get_serial(), user,
                                                     user.login, TO_RESOLVER))
            else:
                print('{0!s}: Could not find user for token in resolver '
                      '{1!s}'.format(token.get_serial(), FROM_RESOLVER))


if __name__ == '__main__':
    main()
