#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import division
from __future__ import print_function

import sys, os

from check_key import get_mac_address_as_string
from check_key import parse_key_file
from check_key import valid_signature
from create_initial_key import sign, md5_4
 
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Usage:', sys.argv[0], 'request_file_name')
        sys.exit(1)

    n = 3333098473
    public_exponent = 65537
    private_exponent = 939472245
    private_key = (n, private_exponent)
    public_key = (n, public_exponent)

    fname = sys.argv[1]
    took_part_in_the_chain = False

    prev_sig = '0'

    game, registers = parse_key_file(fname)
    for i_register, register in enumerate(registers[:-1]):
        nick, location, date, notes, mac_salt, mac_hash, hash, signature = \
                register
        message = ''.join((prev_sig, game, nick, location, date, notes, 
                           mac_salt, mac_hash))

        if not valid_signature(message, signature, public_key):
            print('Bad signature')
            sys.exit(1)

        this_machines_mac_md54 = md5_4(mac_salt+get_mac_address_as_string())

        if mac_hash == this_machines_mac_md54:
            took_part_in_the_chain = True

    if not took_part_in_the_chain:
        print('Unable to answer request. This computer has not taken part on')
        print('the distribution chain that reached the requesting user.')
        print('You have two options:')
        print('- Take a look at the request file and see if you know any other')
        print('  of the listed players')
        print('- Learn to say no')
        sys.exit(1)

    dest_fname = os.path.join(os.getcwd(), 'reply_to_'+fname)
    with open(dest_fname, 'w') as f:
        f.write('='*14+' inDRM key file (https://github.com/debiatan/inDRM) '+
                '='*14+'\n')
        f.write('game: {}\n'.format(game))
        f.write('='*80+'\n')

        for register in registers[:-1]:
            (nick, location, date, notes, mac_salt, 
             mac_hash, hash, signature) = register
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

        (nick, location, date, notes, mac_salt, 
         mac_hash, hash, signature) = registers[-1]

        # Check hash

        message = ''.join((prev_sig, game, nick, location, date, notes, 
                           mac_salt, mac_hash))
        hash_check = md5_4(message)

        if hash != hash_check:
            print('Invalid request file')
            print('Hash provided in certificate differs from the one computed.')
            print('Something fishy is going on.')
            sys.exit(1)     # TODO: Better debug message

        signature = sign(hash, private_key)

        f.write('nick: {}\n'.format(nick))
        f.write('location: {}\n'.format(location))
        f.write('date: {}\n'.format(date))
        f.write('notes: {}\n'.format(notes))
        f.write('mac_salt: {}\n'.format(mac_salt))
        f.write('mac_hash: {}\n'.format(mac_hash))
        f.write('hash: {}\n'.format(hash))
        f.write('signature: {}\n'.format(signature))

    print('Reply has been generated here:')
    print('*** {} ***'.format(dest_fname))
    print('Send this file back to the future happy player!')


