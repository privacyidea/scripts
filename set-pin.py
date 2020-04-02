#!/opt/privacyidea/bin/python
from flask import Flask
from privacyidea.lib.token import set_pin
from privacyidea.lib.user import User
import argparse
from flask_sqlalchemy import SQLAlchemy
from privacyidea.lib.utils import BASE58
from privacyidea.lib.crypto import generate_password
from privacyidea.app import create_app

__doc__ = """
This scripts sets the pin for a token by serial number.

This is a script that can be called by the privacyIDEA script handler.

it takes the arguments

   setpin.py --serial <existing serial>

You can place the script in your scripts directory /etc/privacyidea/scripts/
and use it in the script event handler.

Adapt it (like the TOKENTYPE and REALM) to your needs.

(c) 2020, Cornelius Kölbel <cornelius.koelbel@netknights.it>

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

PIN = "1234"


def setpin(serial):
    app = create_app(config_name="production",
                     config_file="/etc/privacyidea/pi.cfg",
                     silent=True)

    with app.app_context():
        # Set global values
        set_pin(serial, PIN)


parser = argparse.ArgumentParser()
parser.add_argument('--serial', dest='serial')
args = parser.parse_args()
setpin(args.serial)

