#!!/usr/bin/env python
# -*- coding: utf-8 -*-

import time, random, uuid, md5

def unadorned_hex(integer):
    return hex(long(integer))[2:-1]

def get_mac_address_as_string():
    mac = uuid.getnode()
    assert not (mac >> 40)%2    # Abort on synthetic MAC address
    return unadorned_hex(mac)

def sign(message, private_key):
    n, d = private_key
    hash = long(message, 16)
    return unadorned_hex(pow(hash, d, n))

def md5_4(message):
    hash = md5.md5(message).hexdigest()
    chunks = [long(hash[8*i:8*(i+1)], 16) for i in range(4)]
    result = chunks[0] ^ chunks[1] ^ chunks[2] ^ chunks[3]
    return unadorned_hex(result)

# openssl genrsa 32 | openssl rsa -noout -text
n = 3333098473
public_exponent = 65537
private_exponent = 939472245
private_key = (n, private_exponent)

dest_fname = 'key.txt'
game = 'Adventures in inDRMland'
nick = 'debiatan'
location = 'Barcelona'

year, month, day = time.localtime()[:3]
date = '%d/%02d/%02d'%(year, month, day)
notes = 'Enjoy!'
mac_salt = unadorned_hex(random.randrange(2**32))
mac_hash = md5_4(''.join((mac_salt, get_mac_address_as_string())))

prev_sig = '0'
message = ''.join((prev_sig, game, nick, location, date, notes, mac_salt, 
                   mac_hash))
hash = md5_4(message)
signature = sign(hash, private_key)

with open(dest_fname, 'w') as f:
    f.write('='*14+' inDRM key file (https://github.com/debiatan/inDRM) '+
            '='*14+'\n')
    f.write('game: {}\n'.format(game))
    f.write('='*80+'\n')
    f.write('nick: {}\n'.format(nick))
    f.write('location: {}\n'.format(location))
    f.write('date: {}\n'.format(date))
    f.write('notes: {}\n'.format(notes))
    f.write('mac_salt: {}\n'.format(mac_salt))
    f.write('mac_hash: {}\n'.format(mac_hash))
    f.write('hash: {}\n'.format(hash))
    f.write('signature: {}\n'.format(signature))
