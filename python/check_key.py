#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import sys, os, time, random, uuid, md5

def unadorned_hex(integer):
    return hex(long(integer))[2:-1]

def get_mac_address_as_string():
    mac = uuid.getnode()
    assert not (mac >> 40)%2    # Abort on synthetic MAC address
    return unadorned_hex(mac)

def md5_4(message):
    hash = md5.md5(message).hexdigest()
    chunks = [long(hash[8*i:8*(i+1)], 16) for i in range(4)]
    result = chunks[0] ^ chunks[1] ^ chunks[2] ^ chunks[3]
    return unadorned_hex(result)

def parse_key_file(fname):
    def read_field(field_name, line):
        colon_pos = line.find(':')
        assert(line[:colon_pos].strip() == field_name)
        return line[colon_pos+1:].strip()

    game = ''
    nicks, locations, dates, notes, mac_salts, mac_hashes, hashes, signatures =\
            [], [], [], [], [], [], [], []

    with open(fname) as f:
        f.readline()
        game = read_field('game', f.readline())

        while True:
            f.readline()
            nick = f.readline()
            if not nick: break
            nicks.append(read_field('nick', nick))
            locations.append(read_field('location', f.readline()))
            dates.append(read_field('date', f.readline()))
            notes.append(read_field('notes', f.readline()))
            mac_salts.append(read_field('mac_salt', f.readline()))
            mac_hashes.append(read_field('mac_hash', f.readline()))
            hashes.append(read_field('hash', f.readline()))
            signatures.append(read_field('signature', f.readline()))

    return game, zip(nicks, locations, dates, notes, mac_salts, mac_hashes, 
                     hashes, signatures)

def valid_signature(message, signature, public_key):
    n, e = public_key
    int_hash = long(md5_4(message), 16)
    int_signature = long(signature, 16)
    return pow(int_signature, e, n) == int_hash%n

if __name__ == '__main__':
    n = 3333098473
    public_exponent = 65537
    public_key = (n, public_exponent)

    fname = 'key.txt'
    game, registers = parse_key_file(fname)

    prev_sig = '0'

    for i_register, register in enumerate(registers):
        nick, location, date, notes, mac_salt, mac_hash, hash, signature = \
                register
        message = ''.join((prev_sig, game, nick, location, date, notes, 
                           mac_salt, mac_hash))
        if md5_4(message) != hash:
            print('Incorrect hash for register {}'.format(i_register))
            sys.exit(1)
        if not valid_signature(message, signature, public_key):
            print('Bad signature')
            sys.exit(1)

        prev_sig = signature

    mac_address_matches_main_network_interface = True

    last_mac_salt = registers[-1][4]
    this_machines_mac_hash = md5_4(mac_salt+get_mac_address_as_string())

    last_mac_hash = registers[-1][5]
    if last_mac_hash != this_machines_mac_hash:
        mac_address_matches_main_network_interface = False

    if mac_address_matches_main_network_interface:
        print('Signature checks out')
        sys.exit(0)

    print("")
    print("*** Last MAC address does not belong to this computer ***")
    print("You won't be able to play this game unless you convince another")
    print("player to generate a key for you. Let's generate a request file...")
    print("")
    print("Please provide the following data (or press 'enter' to skip):")
    new_nick = raw_input('Name (or nickname): ')
    new_location = raw_input('Location (place of residence): ')
    new_notes = raw_input('Notes (message to future players): ')

    fname = os.path.join(os.getcwd(), 'request.txt')

    with open(fname, 'w') as f:
        f.write('='*14+' inDRM key file (https://github.com/debiatan/inDRM) '+
                '='*14+'\n')
        f.write('game: {}\n'.format(game))
        f.write('='*80+'\n')

        for register in registers:
            nick, location, date, notes, mac_salt, mac_hash, hash, signature = \
                    register
            f.write('nick: {}\n'.format(nick))
            f.write('location: {}\n'.format(location))
            f.write('date: {}\n'.format(date))
            f.write('notes: {}\n'.format(notes))
            f.write('mac_salt: {}\n'.format(mac_salt))
            f.write('mac_hash: {}\n'.format(mac_hash))
            f.write('hash: {}\n'.format(hash))
            f.write('signature: {}\n'.format(signature))
            f.write('='*80+'\n')

            prev_sig = signature

        nick = new_nick
        location = new_location
        notes = new_notes

        mac_salt = unadorned_hex(random.randrange(2**32))
        mac_hash = md5_4(mac_salt+get_mac_address_as_string())

        year, month, day = time.localtime()[:3]
        date = '%d/%02d/%02d'%(year, month, day)

        message = ''.join((prev_sig, game, nick, location, date, notes, 
                           mac_salt, mac_hash))
        hash = md5_4(message)
        f.write('nick: {}\n'.format(nick))
        f.write('location: {}\n'.format(location))
        f.write('date: {}\n'.format(date))
        f.write('notes: {}\n'.format(notes))
        f.write('mac_salt: {}\n'.format(mac_salt))
        f.write('mac_hash: {}\n'.format(mac_hash))
        f.write('hash: {}\n'.format(hash))
        f.write('signature: NO SIGNATURE YET\n')

    print("")
    print("A request file has been generated here:")
    print("*** {} ***".format(fname))
    print("")
    print("In order to finish the registration process, send that file back to")
    print("whoever shared the game with you. That person will be able to")
    print("unlock your copy.")
    print("")
    print("Think twice before sharing this game with other people. If they")
    print("ever try playing the game, they might come back asking you to")
    print("register their copies.")
          
