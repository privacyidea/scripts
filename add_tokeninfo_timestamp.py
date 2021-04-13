#!/opt/privacyidea/bin/python
from privacyidea.lib.token import add_tokeninfo
import argparse
from privacyidea.app import create_app
from privacyidea.lib.tokenclass import DATE_FORMAT
import datetime

__doc__ = """
This event handler script adds a timestamp as a token info. It can e.g. used
at token_init or token_load to mark the token creation date to track token
life cycles.
It relies on the token serial which is given as argument --serial <SERIAL>.

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

tokeninfo_key = "timestamp"
tokeninfo_value = datetime.datetime.now().strftime(DATE_FORMAT)

def add_tokeninfo_creation_time(serial, key, value):
    app = create_app(config_name="production",
                     config_file="/etc/privacyidea/pi.cfg",
                     silent=True)

    with app.app_context():
        add_tokeninfo(serial, key, value)


parser = argparse.ArgumentParser()
parser.add_argument('--serial', dest='serial')
args = parser.parse_args()

add_tokeninfo_creation_time(args.serial, tokeninfo_key,
                            tokeninfo_value)
