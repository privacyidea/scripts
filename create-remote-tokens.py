#!/opt/privacyidea/bin/python
from flask import Flask
from privacyidea.lib.token import init_token
from privacyidea.lib.user import User
import argparse
from privacyidea.app import create_app
import sys
 
__doc__ = """
This script is supposed to be called after a token is created.
It then creates remote tokens for a list of users, these remote tokens then point to the just created token.
This script is ment to be called by the ScriptEvent handler.

 
   create-remote-tokens.py --serial  <serial number> 
    
You can place the script in your scripts directory /etc/privacyidea/scripts/
and use it in the script event handler.

Configure your script handler like:

event: token_init
position: Post
conditions: 
 * tokentype
action:
 * background: background
 * serial: True
 * sync_to_database: True
 
Adapt it (like the USERNAMES) to your needs.
 
(c) 2024, Cornelius Kölbel <cornelius.koelbel@netknights.it>
 
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

# This is a list of users to create remote tokens for
USERNAMES = ["root", "daemon"]
# The realm, where the usernames are located
REALM = "defrealm"
# Get the ID from your database of the remote server
REMOTE_SERVER_ID = 1
# SHould we check the PIN locally of the different users?
REMOTE_LOCAL_CHECK_PIN = False

def create_tokens(serial):
    app = create_app(config_name="production",
                     config_file="/etc/privacyidea/pi.cfg",
                     silent=True)
 
    with app.app_context():
        for username in USERNAMES:
            user = User(username, REALM)
            if not user:
                sys.stderr.write("User {0!s} does not exist.\n".format(username))
                continue

            params = {}
            params["remote.server_id"] = REMOTE_SERVER_ID
            params["remote.serial"] = serial
            params["remote.local_checkpin"] = REMOTE_LOCAL_CHECK_PIN
            params["type"] = "remote"

            remote_token = init_token(params, user=user)
            print("Created remote token {0!s} for user {1!s}.".format(remote_token, username))
 
 
parser = argparse.ArgumentParser()
parser.add_argument('--serial', dest='serial')
args = parser.parse_args()
serial = create_tokens(args.serial)
