#!/usr/bin/env python
#
# btcspy - electrum client history outputter
# Copyright (C) 2011 thomasv@gitorious
# Copyright (C) 2014 David Llewellyn-Jones (david@flypig.co.uk)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

from decimal import Decimal
import json
import optparse
import os
import re
import ast
import sys
import time
import traceback
import inspect

# use this if you want to include modules from a subforder
cmd_subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile( inspect.currentframe() ))[0],"lib")))
if cmd_subfolder not in sys.path:
    sys.path.insert(0, cmd_subfolder)


import simple_config, wallet
from simple_config import *
from commands import *
from util import print_msg, print_stderr, print_json, set_verbosity
from wallet import *

is_local = os.path.dirname(os.path.realpath(__file__)) == os.getcwd()
is_android = 'ANDROID_DATA' in os.environ

#import __builtin__
#__builtin__.use_local_modules = is_local or is_android

## load local module as electrum
#if __builtin__.use_local_modules:
#    import imp
#    #imp.load_module('electrum', *imp.find_module('lib'))

#if is_local:
sys.path.append('lib')


#from electrum import SimpleConfig, Wallet, WalletStorage
#from electrum.util import print_msg, print_stderr, print_json, set_verbosity

# get password routine
def prompt_password(prompt, confirm=True):
    import getpass
    if sys.stdin.isatty():
        password = getpass.getpass(prompt)
        if password and confirm:
            password2 = getpass.getpass("Confirm: ")
            if password != password2:
                sys.exit("Error: Passwords do not match.")
    else:
        password = raw_input(prompt)
    if not password:
        password = None
    return password


def arg_parser():
    usage = "btcspy [options] command"
    details = "Outputs a list of Bitcoin transactions in JSON format taken from the Electrum wallet of the current user. It can also be imported into a Python program using 'import btcspy', after which 'btcspy.history()' will return the history as a structure,"
    parser = optparse.OptionParser(prog=usage, add_help_option=False, description=details)

    parser.add_option("-h", "--help", action="callback", callback=print_help_cb, help="show this help text")
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False, help="show debugging information")
    parser.add_option("-W", "--password", dest="password", default=None, help="set password for usage with commands (currently only implemented for create command, do not use it for longrunning gui session since the password is visible in /proc)")
    parser.add_option("-w", "--wallet", dest="wallet_path", help="wallet path (default: electrum.dat)")
    return parser


def print_help(parser):
    parser.print_help()
    print_msg("Type 'btcspy --help' to see the list of options")
    run_command(known_commands['help'], None)
    sys.exit(1)


def print_help_cb(self, opt, value, parser):
    print_help(parser)


def run_command(cmd, wallet, password=None, args=[]):
    network = None

    cmd_runner = Commands(wallet)
    func = getattr(cmd_runner, cmd.name)
    cmd_runner.password = password
    try:
        result = func(*args[1:])
    except Exception:
        traceback.print_exc(file=sys.stdout)
        sys.exit(1)

    if type(result) == str:
        print_msg(result)
    elif result is not None:
        print_json(result)

def get_command(cmd, wallet, password=None, args=[]):
    network = None

    cmd_runner = Commands(wallet)
    func = getattr(cmd_runner, cmd.name)
    cmd_runner.password = password
    try:
        result = func(*args[1:])
    except Exception:
        traceback.print_exc(file=sys.stdout)
        sys.exit(1)

    return result


if __name__ == '__main__':

    parser = arg_parser()
    options, args = parser.parse_args()
#    if options.wallet_path is None:
#        options.electrum_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'electrum_data')

    config_options = eval(str(options))
    for k, v in config_options.items():
        if v is None:
            config_options.pop(k)

    set_verbosity(config_options.get('verbose'))

    config = SimpleConfig(config_options)

    if len(args) == 0:
        url = None
        cmd = 'history'
    else:
	    cmd = args[0]

    if cmd not in known_commands:
        cmd = 'help'

    cmd = known_commands[cmd]

    # instanciate wallet for command-line
    storage = WalletStorage(config)


    if cmd.requires_wallet and not storage.file_exists:
        print_msg("Error: Wallet file not found.")
        sys.exit(0)


    wallet = Wallet(storage)


    # commands needing password
    if cmd.requires_password:
        if wallet.seed == '':
            seed = ''
            password = None
        elif wallet.use_encryption:
            password = prompt_password('Password:', False)
            if not password:
                print_msg("Error: Password required")
                sys.exit(1)
            # check password
            try:
                seed = wallet.get_seed(password)
            except Exception:
                print_msg("Error: This password does not decode this wallet.")
                sys.exit(1)
        else:
            password = None
            seed = wallet.get_seed(None)
    else:
        password = None

    # add missing arguments, do type conversions
    if cmd.name == 'help':
        if len(args) < 2:
            print_help(parser)

    # check the number of arguments
    argslength = len(args) - 1
    if argslength < 0:
        argslength = 0
    
    if argslength < cmd.min_args:
        print_msg("Not enough arguments")
        print_msg("Syntax:", cmd.syntax)
        sys.exit(1)

    if cmd.max_args >= 0 and argslength > cmd.max_args:
        print_msg("too many arguments", args)
        print_msg("Syntax:", cmd.syntax)
        sys.exit(1)

    if cmd.max_args < 0:
        if len(args) > cmd.min_args + 1:
            message = ' '.join(args[cmd.min_args:])
            print_msg("Warning: Final argument was reconstructed from several arguments:", repr(message))
            args = args[0:cmd.min_args] + [message]



    # run the command
    run_command(cmd, wallet, password, args)


    time.sleep(0.1)
    sys.exit(0)

def history():
    config = SimpleConfig()

    url = None
    cmd = 'history'

    cmd = known_commands[cmd]

    # instanciate wallet for command-line
    storage = WalletStorage(config)


    if cmd.requires_wallet and not storage.file_exists:
        print_msg("Error: Wallet file not found.")
        sys.exit(0)


    wallet = Wallet(storage)

    # commands needing password
    if cmd.requires_password:
        if wallet.seed == '':
            seed = ''
            password = None
        elif wallet.use_encryption:
            password = prompt_password('Password:', False)
            if not password:
                print_msg("Error: Password required")
                sys.exit(1)
            # check password
            try:
                seed = wallet.get_seed(password)
            except Exception:
                print_msg("Error: This password does not decode this wallet.")
                sys.exit(1)
        else:
            password = None
            seed = wallet.get_seed(None)
    else:
        password = None

    # run the command
    return get_command(cmd, wallet, password)



