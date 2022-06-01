#!/opt/privacyidea/bin/python
# -*- coding: utf-8 -*-

from privacyidea.app import create_app
from privacyidea.lib.machine import attach_token
import argparse

__doc__ = """
This is a script that can be called by the privacyIDEA script handler.

It can be used to assign a freshly enrolled SSH-Token to a specific machine (SSH_HOST).
The hostname of the machine must be unique in all machine resolver.

The script takes the arguments

   assign_ssh_token.py --user <existing user> --serial <existing serial>

You can place the script in your scripts directory (default: /etc/privacyidea/scripts/)
and use it in the script event handler with the following configuration:
- 'serial': True
- 'user': True

Adapt SSH_HOST to your needs.

(c) 2022, Cornelius Kölbel <cornelius.koelbel@netknights.it>

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

SSH_HOST = "test_host"
PI_CONFIG = '/etc/privacyidea/pi.cfg'


def assign_ssh_token(serial, username):
    app = create_app(config_name='production',
                     config_file=PI_CONFIG,
                     silent=True)
    with app.app_context():
        attach_token(serial, 'ssh', hostname=SSH_HOST, options={'user': username})


parser = argparse.ArgumentParser()
parser.add_argument('--serial', dest='serial', required=True)
parser.add_argument('--user', dest='username', required=True)
args, unknown = parser.parse_known_args()

# assign the token to a specific machine
if args.serial and args.username:
    assign_ssh_token(args.serial, args.username)
