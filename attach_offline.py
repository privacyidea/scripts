#!/opt/privacyidea/bin/python
# -*- coding: utf-8 -*-

from privacyidea.app import create_app
from privacyidea.lib.machine import attach_token
import argparse

__doc__ = """
This is a script that can be called by the privacyIDEA script handler.

It can be used to attach the offline functionality to a token.

   attach_offline.py --serial <existing serial>

You can place the script in your scripts directory (default: /etc/privacyidea/scripts/)
and use it in the script event handler with the configuration:
- 'background': wait
- 'serial': True
- 'sync_to_database': True


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


PI_CONFIG = '/etc/privacyidea/pi.cfg'


def attach_offline(serial):
    app = create_app(config_name='production',
                     config_file=PI_CONFIG,
                     silent=True)
    with app.app_context():
        attach_token(serial, 'offline')


parser = argparse.ArgumentParser()
parser.add_argument('--serial', dest='serial', required=True)
args, unknown = parser.parse_known_args()

# attach offline
if args.serial:
    attach_offline(args.serial)
