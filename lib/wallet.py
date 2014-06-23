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

import sys
import base64
import os
import re
import hashlib
import copy
import operator
import ast
import threading
import random
#import aes
import Queue
import time
import math

from util import print_msg, print_error, format_satoshis
#from bitcoin import *
from account import *
from transaction import Transaction
#from plugins import run_hook
#import bitcoin
#from synchronizer import WalletSynchronizer

COINBASE_MATURITY = 100
DUST_THRESHOLD = 5430

# internal ID for imported account
IMPORTED_ACCOUNT = '/x'



from version import *


class WalletStorage:

    def __init__(self, config):
        self.lock = threading.Lock()
        self.config = config
        self.data = {}
        self.file_exists = False
        self.path = self.init_path(config)
        print_error( "wallet path", self.path )
        if self.path:
            self.read(self.path)


    def init_path(self, config):
        """Set the path of the wallet."""

        # command line -w option
        path = config.get('wallet_path')
        if path:
            return path

        # path in config file
        path = config.get('default_wallet_path')
        if path:
            return path

        # default path
        dirpath = os.path.join(config.path, "wallets")
        if not os.path.exists(dirpath):
            os.mkdir(dirpath)

        new_path = os.path.join(config.path, "wallets", "default_wallet")

        # default path in pre 1.9 versions
        old_path = os.path.join(config.path, "electrum.dat")
        if os.path.exists(old_path) and not os.path.exists(new_path):
            os.rename(old_path, new_path)

        return new_path


    def read(self, path):
        """Read the contents of the wallet file."""
        try:
            with open(self.path, "r") as f:
                data = f.read()
        except IOError:
            return
        try:
            d = ast.literal_eval( data )  #parse raw data from reading wallet file
        except Exception:
            raise IOError("Cannot read wallet file.")

        self.data = d
        self.file_exists = True


    def get(self, key, default=None):
        v = self.data.get(key)
        if v is None: 
            v = default
        return v

    def put(self, key, value, save = True):

        with self.lock:
            if value is not None:
                self.data[key] = value
            elif key in self.data:
                self.data.pop(key)
            if save: 
                self.write()



class Abstract_Wallet:

    def __init__(self, storage):

        self.storage = storage
        self.electrum_version = ELECTRUM_VERSION
        self.gap_limit_for_change = 3 # constant
        # saved fields
        self.seed_version          = storage.get('seed_version', NEW_SEED_VERSION)
        self.gap_limit             = storage.get('gap_limit', 5)
        self.use_change            = storage.get('use_change',True)
        self.use_encryption        = storage.get('use_encryption', False)
        self.seed                  = storage.get('seed', '')               # encrypted
        self.labels                = storage.get('labels', {})
        self.frozen_addresses      = storage.get('frozen_addresses',[])
        self.addressbook           = storage.get('contacts', [])

        self.history               = storage.get('addr_history',{})        # address -> list(txid, height)

        self.fee                   = int(storage.get('fee_per_kb', 10000))

        self.master_public_keys = storage.get('master_public_keys',{})
        self.master_private_keys = storage.get('master_private_keys', {})

        self.next_addresses = storage.get('next_addresses',{})


        self.load_accounts()

        self.transactions = {}
        tx_list = self.storage.get('transactions',{})
        for k,v in tx_list.items():
            try:
                tx = Transaction(v)
            except Exception:
                print_msg("Warning: Cannot deserialize transactions. skipping")
                continue

            self.add_extra_addresses(tx)
            self.transactions[k] = tx

        for h,tx in self.transactions.items():
            if not self.check_new_tx(h, tx):
                print_error("removing unreferenced tx", h)
                self.transactions.pop(h)


        # not saved
        self.prevout_values = {}     # my own transaction outputs
        self.spent_outputs = []

        # spv
        self.verifier = None

        # there is a difference between wallet.up_to_date and interface.is_up_to_date()
        # interface.is_up_to_date() returns true when all requests have been answered and processed
        # wallet.up_to_date is true when the wallet is synchronized (stronger requirement)
        
        self.up_to_date = False
        self.lock = threading.Lock()
        self.transaction_lock = threading.Lock()
        self.tx_event = threading.Event()

        for tx_hash, tx in self.transactions.items():
            self.update_tx_outputs(tx_hash)


    def add_extra_addresses(self, tx):
        h = tx.hash()
        # find the address corresponding to pay-to-pubkey inputs
        tx.add_extra_addresses(self.transactions)
        for o in tx.d.get('outputs'):
            if o.get('is_pubkey'):
                for tx2 in self.transactions.values():
                    tx2.add_extra_addresses({h:tx})


    def load_accounts(self):
        self.accounts = {}
        self.imported_keys = self.storage.get('imported_keys',{})

        d = self.storage.get('accounts', {})
        for k, v in d.items():
            if k == 0:
                v['mpk'] = self.storage.get('master_public_key')
                self.accounts[k] = OldAccount(v)
            elif v.get('imported'):
                self.accounts[k] = ImportedAccount(v)
            elif v.get('xpub3'):
                self.accounts[k] = BIP32_Account_2of3(v)
            elif v.get('xpub2'):
                self.accounts[k] = BIP32_Account_2of2(v)
            elif v.get('xpub'):
                self.accounts[k] = BIP32_Account(v)
            elif v.get('pending'):
                self.accounts[k] = PendingAccount(v)
            else:
                print_error("cannot load account", v)


    def can_create_accounts(self):
        return False

    def set_up_to_date(self,b):
        with self.lock: self.up_to_date = b

    def is_up_to_date(self):
        with self.lock: return self.up_to_date


    def update(self):
        self.up_to_date = False
        while not self.is_up_to_date(): 
            time.sleep(0.1)

    def is_imported(self, addr):
        account = self.accounts.get(IMPORTED_ACCOUNT)
        if account: 
            return addr in account.get_addresses(0)
        else:
            return False

    def has_imported_keys(self):
        account = self.accounts.get(IMPORTED_ACCOUNT)
        return account is not None

    def set_label(self, name, text = None):
        changed = False
        old_text = self.labels.get(name)
        if text:
            if old_text != text:
                self.labels[name] = text
                changed = True
        else:
            if old_text:
                self.labels.pop(name)
                changed = True

        if changed:
            self.storage.put('labels', self.labels, True)

        run_hook('set_label', name, text, changed)
        return changed

    def addresses(self, include_change = True, _next=True):
        o = []
        for a in self.accounts.keys():
            o += self.get_account_addresses(a, include_change)

        if _next:
            for addr in self.next_addresses.values():
                if addr not in o:
                    o += [addr]
        return o


    def is_mine(self, address):
        return address in self.addresses(True) 


    def is_change(self, address):
        if not self.is_mine(address): return False
        acct, s = self.get_address_index(address)
        if s is None: return False
        return s[0] == 1


    def get_address_index(self, address):

        for account in self.accounts.keys():
            for for_change in [0,1]:
                addresses = self.accounts[account].get_addresses(for_change)
                for addr in addresses:
                    if address == addr:
                        return account, (for_change, addresses.index(addr))

        for k,v in self.next_addresses.items():
            if v == address:
                return k, (0,0)

        raise Exception("Address not found", address)


    def getpubkeys(self, addr):
        assert is_valid(addr) and self.is_mine(addr)
        account, sequence = self.get_address_index(addr)
        a = self.accounts[account]
        return a.get_pubkeys( sequence )


    def get_private_key(self, address, password):
        if self.is_watching_only():
            return []
        account_id, sequence = self.get_address_index(address)
        return self.accounts[account_id].get_private_key(sequence, self, password)


    def get_public_keys(self, address):
        account_id, sequence = self.get_address_index(address)
        return self.accounts[account_id].get_pubkeys(sequence)


    def sign_message(self, address, message, password):
        keys = self.get_private_key(address, password)
        assert len(keys) == 1
        sec = keys[0]
        key = regenerate_key(sec)
        compressed = is_compressed(sec)
        return key.sign_message(message, compressed, address)



    def decrypt_message(self, pubkey, message, password):
        address = public_key_to_bc_address(pubkey.decode('hex'))
        keys = self.get_private_key(address, password)
        secret = keys[0]
        ec = regenerate_key(secret)
        decrypted = ec.decrypt_message(message)
        return decrypted



    def is_found(self):
        return self.history.values() != [[]] * len(self.history) 


    def get_tx_value(self, tx, account=None):
        domain = self.get_account_addresses(account)
        return tx.get_value(domain, self.prevout_values)

    
    def update_tx_outputs(self, tx_hash):
        tx = self.transactions.get(tx_hash)

        for i, (addr, value) in enumerate(tx.outputs):
            key = tx_hash+ ':%d'%i
            self.prevout_values[key] = value

        for item in tx.inputs:
            if self.is_mine(item.get('address')):
                key = item['prevout_hash'] + ':%d'%item['prevout_n']
                self.spent_outputs.append(key)


    def get_addr_balance(self, address):
        #assert self.is_mine(address)
        h = self.history.get(address,[])
        if h == ['*']: return 0,0
        c = u = 0
        received_coins = []   # list of coins received at address

        for tx_hash, tx_height in h:
            tx = self.transactions.get(tx_hash)
            if not tx: continue

            for i, (addr, value) in enumerate(tx.outputs):
                if addr == address:
                    key = tx_hash + ':%d'%i
                    received_coins.append(key)

        for tx_hash, tx_height in h:
            tx = self.transactions.get(tx_hash)
            if not tx: continue
            v = 0

            for item in tx.inputs:
                addr = item.get('address')
                if addr == address:
                    key = item['prevout_hash']  + ':%d'%item['prevout_n']
                    value = self.prevout_values.get( key )
                    if key in received_coins: 
                        v -= value

            for i, (addr, value) in enumerate(tx.outputs):
                key = tx_hash + ':%d'%i
                if addr == address:
                    v += value

            if tx_height:
                c += v
            else:
                u += v
        return c, u


    def get_account_name(self, k):
        return self.labels.get(k, self.accounts[k].get_name(k))


    def get_account_names(self):
        account_names = {}
        for k in self.accounts.keys():
            account_names[k] = self.get_account_name(k)
        return account_names


    def get_account_addresses(self, a, include_change=True):
        if a is None:
            o = self.addresses(True)
        elif a in self.accounts:
            ac = self.accounts[a]
            o = ac.get_addresses(0)
            if include_change: o += ac.get_addresses(1)
        return o


    def get_account_balance(self, account):
        return self.get_balance(self.get_account_addresses(account))

    def get_frozen_balance(self):
        return self.get_balance(self.frozen_addresses)
        
    def get_balance(self, domain=None):
        if domain is None: domain = self.addresses(True)
        cc = uu = 0
        for addr in domain:
            c, u = self.get_addr_balance(addr)
            cc += c
            uu += u
        return cc, uu


    def get_unspent_coins(self, domain=None):
        coins = []
        if domain is None: domain = self.addresses(True)
        for addr in domain:
            h = self.history.get(addr, [])
            if h == ['*']: continue
            for tx_hash, tx_height in h:
                tx = self.transactions.get(tx_hash)
                if tx is None: raise Exception("Wallet not synchronized")
                is_coinbase = tx.inputs[0].get('prevout_hash') == '0'*64
                for o in tx.d.get('outputs'):
                    output = o.copy()
                    if output.get('address') != addr: continue
                    key = tx_hash + ":%d" % output.get('prevout_n')
                    if key in self.spent_outputs: continue
                    output['prevout_hash'] = tx_hash
                    output['height'] = tx_height
                    output['coinbase'] = is_coinbase
                    coins.append((tx_height, output))

        # sort by age
        if coins:
            coins = sorted(coins)
            if coins[-1][0] != 0:
                while coins[0][0] == 0: 
                    coins = coins[1:] + [ coins[0] ]
        return [x[1] for x in coins]


    def get_history(self, address):
        with self.lock:
            return self.history.get(address)


    def get_tx_history(self, account=None):
#        if not self.verifier:
#            return []

        with self.transaction_lock:
            history = self.transactions.items()
            #history.sort(key = lambda x: self.verifier.get_txpos(x[0]))
            result = []
    
            balance = 0
            for tx_hash, tx in history:
                is_relevant, is_mine, v, fee = self.get_tx_value(tx, account)
                if v is not None: balance += v

            c, u = self.get_account_balance(account)

            if balance != c+u:
                result.append( ('', 1000, 0, c+u-balance, None, c+u-balance, None ) )

            balance = c + u - balance
            for tx_hash, tx in history:
                is_relevant, is_mine, value, fee = self.get_tx_value(tx, account)
                if not is_relevant:
                    continue
                if value is not None:
                    balance += value

                conf, timestamp = self.verifier.get_confirmations(tx_hash) if self.verifier else (None, None)
                result.append( (tx_hash, conf, is_mine, value, fee, balance, timestamp) )

        return result


    def get_label(self, tx_hash):
        label = self.labels.get(tx_hash)
        is_default = (label == '') or (label is None)
        if is_default: label = self.get_default_label(tx_hash)
        return label, is_default


    def get_default_label(self, tx_hash):
        tx = self.transactions.get(tx_hash)
        default_label = ''
        if tx:
            is_relevant, is_mine, _, _ = self.get_tx_value(tx)
            if is_mine:
                for o in tx.outputs:
                    o_addr, _ = o
                    if not self.is_mine(o_addr):
                        try:
                            default_label = self.labels[o_addr]
                        except KeyError:
                            default_label = '>' + o_addr
                        break
                else:
                    default_label = '(internal)'
            else:
                for o in tx.outputs:
                    o_addr, _ = o
                    if self.is_mine(o_addr) and not self.is_change(o_addr):
                        break
                else:
                    for o in tx.outputs:
                        o_addr, _ = o
                        if self.is_mine(o_addr):
                            break
                    else:
                        o_addr = None

                if o_addr:
                    dest_label = self.labels.get(o_addr)
                    try:
                        default_label = self.labels[o_addr]
                    except KeyError:
                        default_label = '<' + o_addr

        return default_label


    def sign_transaction(self, tx, keypairs, password):
        tx.sign(keypairs)
        run_hook('sign_transaction', tx, password)


    def check_new_tx(self, tx_hash, tx):
        # 1 check that tx is referenced in addr_history. 
        addresses = []
        for addr, hist in self.history.items():
            if hist == ['*']:continue
            for txh, height in hist:
                if txh == tx_hash: 
                    addresses.append(addr)

        if not addresses:
            return False

        # 2 check that referencing addresses are in the tx
        for addr in addresses:
            if not tx.has_address(addr):
                return False

        return True


class Deterministic_Wallet(Abstract_Wallet):

    def __init__(self, storage):
        Abstract_Wallet.__init__(self, storage)

    def has_seed(self):
        return self.seed != ''

    def is_deterministic(self):
        return True

    def is_watching_only(self):
        return not self.has_seed()

    def get_seed(self, password):
        return pw_decode(self.seed, password)

    def get_mnemonic(self, password):
        return self.get_seed(password)
        
    def num_unused_trailing_addresses(self, addresses):
        k = 0
        for a in addresses[::-1]:
            if self.history.get(a):break
            k = k + 1
        return k

    def min_acceptable_gap(self):
        # fixme: this assumes wallet is synchronized
        n = 0
        nmax = 0

        for account in self.accounts.values():
            addresses = account.get_addresses(0)
            k = self.num_unused_trailing_addresses(addresses)
            for a in addresses[0:-k]:
                if self.history.get(a):
                    n = 0
                else:
                    n += 1
                    if n > nmax: nmax = n
        return nmax + 1


    def address_is_old(self, address):
        age = -1
        h = self.history.get(address, [])
        return False
#        if h == ['*']:
#            return True
#        for tx_hash, tx_height in h:
#            if tx_height == 0:
#                tx_age = 0
#            else:
#                tx_age = self.network.get_local_height() - tx_height + 1
#            if tx_age > age:
#                age = tx_age
#        return age > 2


class OldWallet(Deterministic_Wallet):

    def get_seed(self, password):
        seed = pw_decode(self.seed, password).encode('utf8')
        return seed

    def check_password(self, password):
        seed = self.get_seed(password)
        self.accounts[0].check_seed(seed)

    def get_mnemonic(self, password):
        import mnemonic
        s = self.get_seed(password)
        return ' '.join(mnemonic.mn_encode(s))

# former WalletFactory
class Wallet(object):

    def __new__(self, storage):
        config = storage.config

        if not storage.file_exists:
            print ("Wallet does no exist")
            sys.exit(1)

        seed_version = storage.get('seed_version')
        if not seed_version:
            seed_version = OLD_SEED_VERSION if len(storage.get('master_public_key')) == 128 else NEW_SEED_VERSION

        if seed_version == OLD_SEED_VERSION:
            return OldWallet(storage)
        elif seed_version == NEW_SEED_VERSION:
            return NewWallet(storage)
        else:
            msg = "This wallet seed is not supported."
            if seed_version in [5]:
                msg += "\nTo open this wallet, try 'git checkout seed_v%d'"%seed_version
            print msg
            sys.exit(1)


