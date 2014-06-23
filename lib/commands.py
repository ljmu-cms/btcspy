#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 thomasv@gitorious
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

import time
from util import *
#from bitcoin import *
from decimal import Decimal
#import bitcoin
#from transaction import Transaction

class Command:
    def __init__(self, name, min_args, max_args, requires_network, requires_wallet, requires_password, description, syntax = '', options_syntax = ''):
        self.name = name
        self.min_args=min_args
        self.max_args = max_args
        self.requires_network = requires_network
        self.requires_wallet = requires_wallet
        self.requires_password = requires_password
        self.description = description
        self.syntax = syntax
        self.options = options_syntax

known_commands = {}
def register_command(*args):
    global known_commands
    name = args[0]
    known_commands[name] = Command(*args)



payto_options = ' --fee, -f: set transaction fee\n --fromaddr, -F: send from address -\n --changeaddr, -c: send change to address'
listaddr_options = " -a: show all addresses, including change addresses\n -l: include labels in results"
restore_options = " accepts a seed or master public key."
mksendmany_syntax = 'mksendmanytx <recipient> <amount> [<recipient> <amount> ...]'
payto_syntax = "payto <recipient> <amount> [label]\n<recipient> can be a bitcoin address or a label"
paytomany_syntax = "paytomany <recipient> <amount> [<recipient> <amount> ...]\n<recipient> can be a bitcoin address or a label"
signmessage_syntax = 'signmessage <address> <message>\nIf you want to lead or end a message with spaces, or want double spaces inside the message make sure you quote the string. I.e. " Hello  This is a weird String "'
verifymessage_syntax = 'verifymessage <address> <signature> <message>\nIf you want to lead or end a message with spaces, or want double spaces inside the message make sure you quote the string. I.e. " Hello  This is a weird String "'


#                command
#                                              requires_network
#                                                     requires_wallet
#                                                            requires_password
register_command('history',              0, 0, True,  True,  False, 'Returns the transaction history of your wallet')
register_command('help',                 0, 1, False, False, False, 'Prints this help')




class Commands:

    def __init__(self, wallet, callback = None):
        self.wallet = wallet
        #self.network = network
        self._callback = callback
        self.password = None


    def _run(self, method, args, password_getter):
        cmd = known_commands[method]
        if cmd.requires_password and self.wallet.use_encryption:
            self.password = apply(password_getter,())
        f = getattr(self, method)
        result = f(*args)
        self.password = None
        if self._callback:
            apply(self._callback, ())
        return result


    def help(self, cmd=None):
        if cmd not in known_commands:
            print_msg("\nList of commands:", ', '.join(sorted(known_commands)))
        else:
            cmd = known_commands[cmd]
            print_msg(cmd.description)
            if cmd.syntax: print_msg("Syntax: " + cmd.syntax)
            if cmd.options: print_msg("options:\n" + cmd.options)
        return None


    def history(self):
        import datetime
        balance = 0
        out = []
        for item in self.wallet.get_tx_history():
            tx_hash, conf, is_mine, value, fee, balance, timestamp = item
            try:
                time_str = datetime.datetime.fromtimestamp( timestamp).isoformat(' ')[:-3]
            except Exception:
                time_str = "----"

            label, is_default_label = self.wallet.get_label(tx_hash)

            out.append({'txid':tx_hash, 'date':"%16s"%time_str, 'label':label, 'value':format_satoshis(value)})
        return out




