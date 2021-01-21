#!/usr/bin/env python3

'''
journal.py is script that encodes a journal/text file using a key
'''

import getpass
import bcrypt
import os.path
from os import path

def get_password():
    '''
    Check if password already exists and if not,
    create a new password for the journal.
    If password exists, get password from user to verify
    '''

    if(path.exists('./secret')):
        password = getpass.getpass('Please enter your password: ')
        password = password.encode('utf-8')

        if(password_verify(password)):
            print('WE DID IT')

        else:
            print('UNAUTHORIZED: PASSWORD INCORRECT')

    else:
        # get a new password
        password = getpass.getpass('Please enter a new password: ')
        confirm_password = getpass.getpass('Please confirm your password: ')

        if(password == confirm_password):
            print('PASSWORD CONFIRMED\n')

            # encode and save password
            password = password.encode('utf-8')
            save_password(password)

        else:
            print('SORRY, THOSE PASSWORDS DO NOT MATCH\n')
            get_password()


def save_password(password):
    ''' Saves a hashed password in secrets file '''

    # hash password
    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt(8))

    # save to binary file
    secret_file = open('secret', 'wb')
    secret_file.write(hashed_password)
    secret_file.close()

    print('NEW PASSWORD SAVED')


def password_verify(password):
    ''' Reads secret file and check's hash against entered password '''

    # Read secret file
    secret_file = open('secret', 'rb')
    hashed_password = secret_file.read()

    if(bcrypt.checkpw(password, hashed_password)):
        return True
    else:
        return False




##########

get_password()
